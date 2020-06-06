package wanted

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	Version = "0.1.3"

	BroadcastMessage = "fire"
	ArgStdin         = "-"

	StateNone State = iota
	StateStopping
	StateWaiting
	StateCleaning
	StateDone
)

type State int

type state struct {
	sync.Mutex
	v State
}

type WantedError struct {
	State       State
	Description string
}

func (e *WantedError) Error() string {
	return e.Description + ": " + strconv.Itoa(int(e.State))
}

type Wanted struct {
	config   Config
	errors   chan error
	stopchan chan struct{}
	state    state
}

func (w *Wanted) Check() error {
	return w.config.check()
}

func (w *Wanted) StartMonitor(broadcast bool) error {
	w.state.Lock()
	defer w.state.Unlock()
	v := w.state.v
	if v == StateNone {
		if broadcast {
			if err := w.startBroadcastMonitor(); err != nil {
				return err
			}
		} else {
			go w.startSignalMonitor()
		}
		w.state.v = StateWaiting
		return nil
	}
	return &WantedError{v, "invalid state"}
}

func (w *Wanted) stop() {
	w.state.Lock()
	defer w.state.Unlock()
	if w.state.v != StateCleaning {
		w.state.v = StateNone
	}
}

func (w *Wanted) startBroadcastMonitor() error {
	network := "udp4"
	inaddr, err := net.ResolveUDPAddr(network, w.config.Async.Broadcast.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP(network, inaddr)
	if err != nil {
		return err
	}
	prefix := "broadcast listener:"
	log.Printf("%s %q\n", prefix, inaddr)
	password := w.config.Async.Broadcast.Password
	stopchan := make(chan struct{}, 1)
	firechan := make(chan struct{}, 1)
	handler := func(data []byte) {
		data, err := decryptAESGCM(password, data)
		if err != nil {
			log.Println("decrypt:", err)
			return
		}
		if string(data) != BroadcastMessage {
			return
		}
		w.state.Lock()
		defer w.state.Unlock()
		if w.state.v == StateWaiting {
			w.state.v = StateCleaning
			firechan <- struct{}{}
		}
	}
	go func() {
		select {
		case <-firechan:
			closerchan := make(chan bool, 1)
			go func() {
				timer := time.AfterFunc(100*time.Millisecond, func() {
					closerchan <- false
				})
				defer timer.Stop()
				conn.SetDeadline(time.Now().Add(50 * time.Millisecond))
				conn.Close()
				closerchan <- true
			}()
			if !<-closerchan {
				log.Println(prefix, "connection close timeout")
			}
			w.fire()
		case <-w.stopchan:
			conn.Close()
		case <-stopchan:
		}
	}()
	go func() {
		defer w.stop()
		defer conn.Close()
		for {
			buf := make([]byte, 1<<8)
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				log.Println(prefix, err)
				stopchan <- struct{}{}
				return
			}
			go handler(buf[:n])
		}
	}()
	return nil
}

func (w *Wanted) startSignalMonitor() {
	sigstop := make(chan struct{}, 1)
	firechan := make(chan struct{}, 1)
	go func() {
		defer w.stop()
		arm := func() {
			w.state.Lock()
			defer w.state.Unlock()
			if w.state.v == StateWaiting {
				w.state.v = StateCleaning
				firechan <- struct{}{}
			}
		}
		threshold := w.config.Notify.Threshold
		prethreshold := threshold - 1
		delay := w.config.Notify.Delay.Unwrap()
		sigchan := make(chan os.Signal, threshold*2+1)
		signal.Notify(
			sigchan,
			syscall.SIGUSR1,
			syscall.SIGUSR2,
			syscall.SIGHUP,
		)
		defer signal.Stop(sigchan)
		i := 0
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case sig := <-sigchan:
				switch sig {
				case syscall.SIGUSR1:
					i++
					if i == threshold {
						timer = time.AfterFunc(delay, arm)
					}
				case syscall.SIGUSR2:
					if i > 0 {
						i--
						if i == prethreshold {
							timer.Stop()
						}
					}
				case syscall.SIGHUP:
					if err := w.reconfig(); err != nil {
						log.Println("HUP:", err)
					} else {
						isArmed := i >= threshold
						delay = w.config.Notify.Delay.Unwrap()
						threshold = w.config.Notify.Threshold
						prethreshold = threshold - 1
						if i >= threshold && !isArmed {
							timer = time.AfterFunc(delay, arm)
						} else if i <= prethreshold && isArmed {
							timer.Stop()
						}
					}
				}
			case <-sigstop:
				return
			}
		}
	}()
	select {
	case <-firechan:
		sigstop <- struct{}{}
		w.fire()
	case <-w.stopchan:
		sigstop <- struct{}{}
	}
}

func (w *Wanted) fire() {
	log.Println("Fired at:", time.Now().Format(time.RFC1123Z))
	w.clean()
	w.state.Lock()
	w.state.v = StateDone
	w.state.Unlock()
	close(w.errors)
}

func (w *Wanted) StopMonitor() bool {
	w.state.Lock()
	defer w.state.Unlock()
	if w.state.v == StateWaiting {
		w.state.v = StateStopping
		w.stopchan <- struct{}{}
		return true
	}
	return false
}

func (w *Wanted) Errors() <-chan error {
	return w.errors
}

func (w *Wanted) IsDone() bool {
	w.state.Lock()
	v := w.state.v
	w.state.Unlock()
	return v == StateDone
}

func (w *Wanted) reconfig() error {
	var config Config
	if err := config.Set(w.config.path); err != nil {
		return err
	}
	config.prepare()
	if err := config.check(); err != nil {
		return err
	}
	n := config.errorsCap()
	if cap(w.errors) < n {
		close(w.errors)
		w.errors = make(chan error, n)
	}
	w.config = config
	return nil
}

func (w *Wanted) clean() {
	w.doAsync()
	w.doKill()
	w.doRemove()
	w.doRun()
}

func (w *Wanted) doAsync() {
	waitchan := make(chan bool, 1)
	go func() {
		timer := time.AfterFunc(
			w.config.Async.Timeout.Unwrap()+w.config.Async.Delay.Unwrap(),
			func() { waitchan <- false },
		)
		defer timer.Stop()
		var wg sync.WaitGroup
		w.doAsyncBroadcast(&wg)
		w.doAsyncRun(&wg)
		w.doAsyncRequest(&wg)
		w.doAsyncMail(&wg)
		wg.Wait()
		waitchan <- true
	}()
	if !<-waitchan {
		w.errors <- errors.New("async timeout")
	}
}

func (w *Wanted) doAsyncBroadcast(wg *sync.WaitGroup) {
	n := w.config.Async.Broadcast.len()
	if n > 0 {
		wg.Add(n)
		deadline := time.Now().Add(w.config.Async.Timeout.Unwrap())
		go func() {
			defer wg.Done()
			msg, err := encryptAESGCM(
				w.config.Async.Broadcast.Password,
				[]byte(BroadcastMessage),
			)
			if err != nil {
				w.errors <- err
				return
			}
			sendBroadcast(
				w.config.Async.Broadcast.Addr,
				msg,
				w.errors,
				deadline,
			)
		}()
	}
}

func (w *Wanted) doAsyncRun(wg *sync.WaitGroup) {
	n := w.config.Async.Run.len()
	if n > 0 {
		wg.Add(n)
		timeout := w.config.Async.Timeout.Unwrap()
		self := w.config.Async.Run
		env := self.env()
		run := func(command string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			args := self.args()
			args[len(args)-1] = command
			cmd := exec.CommandContext(ctx, args[0], args[1:]...)
			cmd.Env = env
			w.errors <- cmd.Run()
		}
		for _, command := range self.Commands {
			go run(command)
		}
	}
}

func (w *Wanted) doAsyncRequest(wg *sync.WaitGroup) {
	n := w.config.Async.Request.len()
	if n > 0 {
		wg.Add(n)
		httpClient := &http.Client{Timeout: w.config.Async.Timeout.Unwrap()}
		files := w.config.Async.Request.Files
		hasFiles := len(files) > 0
		compress := *w.config.Async.Request.Compress
		request := func(url string) {
			defer wg.Done()
			if hasFiles {
				postFiles(httpClient, url, files, w.errors, true, compress)
			} else {
				if resp, err := httpClient.Get(url); err != nil {
					w.errors <- err
				} else {
					resp.Body.Close()
				}
			}
		}
		for _, url := range w.config.Async.Request.Urls {
			go request(url)
		}
	}
}

func (w *Wanted) doAsyncMail(wg *sync.WaitGroup) {
	n := w.config.Async.Mail.len()
	if n > 0 {
		wg.Add(n)
		isMultihost := n > 1
		timeout := w.config.Async.Timeout.Unwrap()
		deadline := time.Now().Add(timeout)
		from := w.config.Async.Mail.From
		username := w.config.Async.Mail.Username
		password := w.config.Async.Mail.Password
		msg := emailMessage{}
		for _, to := range w.config.Async.Mail.To {
			msg.AddTo("", to)
		}
		msg.Subject = w.config.Async.Mail.Subject
		msg.Body = w.config.Async.Mail.Body
		compress := *w.config.Async.Mail.Compress
		for _, path := range w.config.Async.Mail.Files {
			if err := msg.AddAttachment(path, compress); err != nil {
				w.errors <- err
			}
		}
		addDomain := func(s, domain string) string {
			return s + "@" + domain
		}
		mail := func(host string) {
			defer wg.Done()
			msg1 := msg
			from := from
			username := username
			hostname := getHostnameFromHost(host)
			if isMultihost {
				domain := getDomainFromHostname(hostname)
				from = addDomain(from, domain)
				username = addDomain(username, domain)
			}
			msg1.SetFrom("", from)
			if err := sendMailTLS(
				host,
				smtp.PlainAuth("", username, password, hostname),
				msg1,
				timeout,
				deadline,
			); err != nil {
				w.errors <- err
			}
		}
		for _, host := range w.config.Async.Mail.Hosts {
			go mail(host)
		}
	}
}

func (w *Wanted) doKill() {
	signal := w.config.Kill.Signal
	kill := func(pid int) {
		if err := syscall.Kill(pid, signal); err != nil {
			w.errors <- &KillError{pid, err}
		}
	}
	for _, pid := range w.config.Kill.Pids {
		kill(pid)
	}
	for _, path := range w.config.Kill.PidFiles {
		content, err := ioutil.ReadFile(path)
		if err != nil {
			w.errors <- err
			continue
		}
		pid, err := strconv.Atoi(string(bytes.TrimSpace(content)))
		if err != nil {
			w.errors <- err
			continue
		}
		kill(pid)
	}
}

func (w *Wanted) doRemove() {
	for _, path := range w.config.Remove.Paths {
		w.errors <- os.RemoveAll(path)
	}
}

func (w *Wanted) doRun() {
	if w.config.Run.len() > 0 {
		args := w.config.Run.args()
		idx := len(args) - 1
		env := w.config.Run.env()
		for _, command := range w.config.Run.Commands {
			args[idx] = command
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Env = env
			w.errors <- cmd.Run()
		}
	}
}

func NewWanted(c Config) *Wanted {
	c.prepare()
	return &Wanted{
		config:   c,
		errors:   make(chan error, c.errorsCap()),
		stopchan: make(chan struct{}),
		state:    state{v: StateNone},
	}
}
