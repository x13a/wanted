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
	Version = "0.1.6"

	BroadcastMessage = "fire"
	ArgStdin         = "-"
)

const (
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

func (s *state) Get() (value State) {
	s.Lock()
	value = s.v
	s.Unlock()
	return
}

func (s *state) Set(value State) {
	s.Lock()
	s.v = value
	s.Unlock()
}

func (s *state) CompareAndSwap(old State, new State) (swapped bool) {
	s.Lock()
	if s.v == old {
		s.v = new
		swapped = true
	}
	s.Unlock()
	return
}

type WantedError struct {
	Op          string
	State       State
	Description string
}

func (e *WantedError) Error() string {
	return e.Op + " > " + e.Description + ": " + strconv.Itoa(int(e.State))
}

type Wanted struct {
	config   Config
	errors   chan error
	stopchan chan struct{}
	state    state
	udpConn  *net.UDPConn
}

func (w *Wanted) Check() error {
	w.state.Lock()
	defer w.state.Unlock()
	v := w.state.v
	if v == StateNone {
		return w.config.check()
	}
	return &WantedError{"check", v, "invalid state"}
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
			w.startSignalMonitor()
		}
		w.state.v = StateWaiting
		return nil
	}
	return &WantedError{"start monitor", v, "invalid state"}
}

func (w *Wanted) stop() {
	w.state.Set(StateNone)
}

func (w *Wanted) startBroadcastMonitor() error {
	network := "udp4"
	addr, err := net.ResolveUDPAddr(network, w.config.Async.Broadcast.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP(network, addr)
	if err != nil {
		return err
	}
	log.Printf("broadcast listener: %q\n", addr)
	firechan := make(chan struct{})
	stopchan := make(chan struct{}, 1)
	readstop := make(chan struct{})
	go func() {
		select {
		case <-firechan:
			close(readstop)
			if w.config.Async.Broadcast.len() != 0 {
				conn.SetReadDeadline(time.Now())
				w.udpConn = conn
			} else {
				go func() { conn.Close() }()
			}
			w.fire()
		case <-w.stopchan:
			close(readstop)
			conn.Close()
			<-stopchan
			w.stop()
		}
	}()
	go func() {
		password := w.config.Async.Broadcast.Password
		handler := func(data []byte) {
			data, err := decryptAESGCM(password, data)
			if err != nil {
				log.Println("decrypt:", err)
				return
			}
			if string(data) != BroadcastMessage {
				log.Println("got invalid message")
				return
			}
			if w.state.CompareAndSwap(StateWaiting, StateCleaning) {
				close(firechan)
			}
		}
		i := 0
		maxRetries := 3
		for {
			buf := make([]byte, 1<<8)
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-readstop:
					stopchan <- struct{}{}
					return
				default:
				}
				i++
				if i == maxRetries {
					panic(err)
				}
				log.Println(err)
				continue
			}
			go handler(buf[:n])
		}
	}()
	return nil
}

func (w *Wanted) startSignalMonitor() {
	firechan := make(chan struct{})
	stopchan := make(chan struct{}, 2)
	sigstop := make(chan struct{})
	go func() {
		select {
		case <-firechan:
			close(sigstop)
			w.fire()
		case <-w.stopchan:
			close(sigstop)
			for i, n := 0, cap(stopchan); i < n; i++ {
				<-stopchan
			}
			w.stop()
		}
	}()
	hupchan := make(chan struct{}, 1)
	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, syscall.SIGHUP)
		defer signal.Stop(sigchan)
		for {
			select {
			case <-sigchan:
				ok, err := w.reconfig()
				if !ok {
					return
				}
				if err != nil {
					log.Println("HUP:", err)
					break
				}
				select {
				case <-hupchan:
				default:
				}
				hupchan <- struct{}{}
			case <-sigstop:
				stopchan <- struct{}{}
				return
			}
		}
	}()
	go func() {
		arm := func() {
			if w.state.CompareAndSwap(StateWaiting, StateCleaning) {
				close(firechan)
			}
		}
		threshold := w.config.Notify.Threshold
		prethreshold := threshold - 1
		delay := w.config.Notify.Delay.Unwrap()
		sigchan := make(chan os.Signal, threshold<<2)
		signal.Notify(sigchan, syscall.SIGUSR1, syscall.SIGUSR2)
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
				}
			case <-hupchan:
				isArmed := i >= threshold
				threshold = w.config.Notify.Threshold
				prethreshold = threshold - 1
				delay = w.config.Notify.Delay.Unwrap()
				if i >= threshold && !isArmed {
					timer = time.AfterFunc(delay, arm)
				} else if i <= prethreshold && isArmed {
					timer.Stop()
				}
			case <-sigstop:
				stopchan <- struct{}{}
				return
			}
		}
	}()
}

func (w *Wanted) fire() {
	log.Println("Fired at:", time.Now().Format(time.RFC1123Z))
	w.clean()
	w.state.Set(StateDone)
	close(w.errors)
}

func (w *Wanted) StopMonitor() bool {
	if w.state.CompareAndSwap(StateWaiting, StateStopping) {
		w.stopchan <- struct{}{}
		return true
	}
	return false
}

func (w *Wanted) Errors() <-chan error {
	return w.errors
}

func (w *Wanted) State() State {
	return w.state.Get()
}

func (w *Wanted) reconfig() (bool, error) {
	ok := true
	config := Config{}
	if err := config.Set(w.config.path); err != nil {
		return ok, err
	}
	config.prepare()
	if err := config.check(); err != nil {
		return ok, err
	}
	ok = false
	w.state.Lock()
	if w.state.v < StateCleaning {
		if n := config.errorsCap(); cap(w.errors) < n {
			close(w.errors)
			w.errors = make(chan error, n)
		}
		w.config = config
		ok = true
	}
	w.state.Unlock()
	return ok, nil
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
		timeout := w.config.Async.Timeout.Unwrap()
		deadline := time.Now().Add(timeout)
		timer := time.AfterFunc(
			timeout+w.config.Async.Delay.Unwrap(),
			func() { waitchan <- false },
		)
		defer timer.Stop()
		var wg sync.WaitGroup
		w.doAsyncBroadcast(&wg, deadline)
		w.doAsyncRun(&wg, deadline)
		w.doAsyncRequest(&wg, deadline)
		w.doAsyncMail(&wg, deadline)
		wg.Wait()
		waitchan <- true
	}()
	if !<-waitchan {
		w.errors <- errors.New("async timeout")
	}
}

func (w *Wanted) doAsyncBroadcast(wg *sync.WaitGroup, deadline time.Time) {
	n := w.config.Async.Broadcast.len()
	if n == 0 {
		return
	}
	wg.Add(n)
	go func() {
		defer wg.Done()
		if w.udpConn != nil {
			defer w.udpConn.Close()
		}
		msg, err := encryptAESGCM(
			w.config.Async.Broadcast.Password,
			[]byte(BroadcastMessage),
		)
		if err != nil {
			w.errors <- err
			return
		}
		errorsCap := w.config.Async.Broadcast.errorsCap() - 1
		errchan := make(chan error, errorsCap)
		sendBroadcast(
			w.udpConn,
			w.config.Async.Broadcast.Addr,
			msg,
			errchan,
			deadline,
		)
		i := 0
		for err = range errchan {
			if i > errorsCap {
				log.Println(err)
				continue
			}
			i++
			w.errors <- err
			if i == errorsCap {
				i++
				w.errors <- errors.New("too many broadcast errors")
			}
		}
	}()
}

func (w *Wanted) doAsyncRun(wg *sync.WaitGroup, deadline time.Time) {
	n := w.config.Async.Run.len()
	if n == 0 {
		return
	}
	wg.Add(n)
	go func() {
		args := w.config.Async.Run.args()
		lenArgs := len(args)
		idx := lenArgs - 1
		env := w.config.Async.Run.env()
		run := func(command string) {
			defer wg.Done()
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			args1 := make([]string, lenArgs)
			copy(args1, args)
			args1[idx] = command
			cmd := exec.CommandContext(ctx, args1[0], args1[1:]...)
			cmd.Env = env
			if err := cmd.Run(); err != nil {
				w.errors <- err
			}
		}
		for _, command := range w.config.Async.Run.Commands {
			go run(command)
		}
	}()
}

func (w *Wanted) doAsyncRequest(wg *sync.WaitGroup, deadline time.Time) {
	n := w.config.Async.Request.len()
	if n == 0 {
		return
	}
	wg.Add(n)
	go func() {
		httpClient := &http.Client{Timeout: w.config.Async.Timeout.Unwrap()}
		files := w.config.Async.Request.Files
		hasFiles := len(files) != 0
		compress := *w.config.Async.Request.Compress
		errorsCap := w.config.Async.Request.errorsCapPerItem()
		request := func(url string) {
			defer wg.Done()
			if hasFiles {
				errchan := make(chan error, errorsCap)
				postFiles(
					httpClient,
					url,
					files,
					errchan,
					true,
					compress,
					deadline,
				)
				for err := range errchan {
					w.errors <- err
				}
			} else {
				ctx, cancel := context.WithDeadline(
					context.Background(),
					deadline,
				)
				defer cancel()
				req, err := http.NewRequestWithContext(
					ctx,
					http.MethodGet,
					url,
					nil,
				)
				if err != nil {
					w.errors <- err
					return
				}
				if resp, err := httpClient.Do(req); err != nil {
					w.errors <- err
				} else {
					resp.Body.Close()
				}
			}
		}
		for _, url := range w.config.Async.Request.Urls {
			go request(url)
		}
	}()
}

func (w *Wanted) doAsyncMail(wg *sync.WaitGroup, deadline time.Time) {
	n := w.config.Async.Mail.len()
	if n == 0 {
		return
	}
	wg.Add(n)
	go func() {
		isMultihost := n > 1
		timeout := w.config.Async.Timeout.Unwrap()
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
			if !time.Now().Before(deadline) {
				for i := 0; i < n; i++ {
					wg.Done()
				}
				return
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
	}()
}

func (w *Wanted) doKill() {
	if w.config.Kill.len() == 0 {
		return
	}
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
	for _, path := range w.config.Remove.FilesSecure {
		if err := srm(path, true); err != nil {
			w.errors <- err
		}
	}
	for _, path := range w.config.Remove.Paths {
		if err := os.RemoveAll(path); err != nil {
			w.errors <- err
		}
	}
}

func (w *Wanted) doRun() {
	if w.config.Run.len() == 0 {
		return
	}
	args := w.config.Run.args()
	idx := len(args) - 1
	env := w.config.Run.env()
	for _, command := range w.config.Run.Commands {
		args[idx] = command
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Env = env
		if err := cmd.Run(); err != nil {
			w.errors <- err
		}
	}
}

func NewWanted(c Config) *Wanted {
	c.prepare()
	return &Wanted{
		config:   c,
		errors:   make(chan error, c.errorsCap()),
		stopchan: make(chan struct{}, 1),
		state:    state{v: StateNone},
		udpConn:  nil,
	}
}
