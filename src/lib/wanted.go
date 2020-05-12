package wanted

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	mailpkg "net/mail"
	"net/smtp"
	urlpkg "net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	Version = "0.0.8"

	envPrefix       = "WANTED_"
	EnvMailUsername = envPrefix + "MAIL_USERNAME"
	EnvMailPassword = envPrefix + "MAIL_PASSWORD"

	DefaultTimeout     = Duration(1 << 4 * time.Second)
	DefaultSignal      = syscall.SIGKILL
	FallbackExecutable = "/bin/sh"

	ArgStdin = "-"
)

type Config struct {
	Notify Notify `json:"notify"`
	Async  Async  `json:"async"`
	Kill   Kill   `json:"kill"`
	Remove Remove `json:"remove"`
	Run    Run    `json:"run"`
	path   string
}

func (c Config) Path() string {
	return c.path
}

func (c Config) String() string {
	return ""
}

func (c *Config) Set(s string) error {
	var file *os.File
	var err error
	if s == ArgStdin {
		file = os.Stdin
	} else {
		file, err = os.Open(s)
		if err != nil {
			return err
		}
		defer file.Close()
	}
	if err = json.NewDecoder(file).Decode(c); err != nil {
		return err
	}
	c.path = s
	return nil
}

func (c *Config) prepare() {
	c.Async.prepare()
	c.Kill.prepare()
	c.Run.prepare()
}

func (c Config) len() int {
	return c.Async.len() + c.Kill.len() + c.Remove.len() + c.Run.len()
}

func (c Config) errorsCap() int {
	return c.len() + len(c.Async.Request.Files)*c.Async.Request.len()
}

func (c *Config) check() error {
	if err := c.Async.check(); err != nil {
		return err
	}
	if err := c.Kill.check(); err != nil {
		return err
	}
	if err := c.Run.check(); err != nil {
		return err
	}
	return nil
}

type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	var v time.Duration
	var err error
	if s == "" {
		v = 0
	} else {
		v, err = time.ParseDuration(s)
		if err != nil {
			return err
		}
	}
	*d = Duration(v)
	return nil
}

func (d Duration) Unwrap() time.Duration {
	return time.Duration(d)
}

type Notify struct {
	Threshold int      `json:"threshold"`
	Delay     Duration `json:"delay"`
}

type CheckError struct {
	Op          string
	Value       interface{}
	Description string
}

func (e *CheckError) Error() string {
	return fmt.Sprintf("%s > %s: %v", e.Op, e.Description, e.Value)
}

type Request struct {
	Urls  []string `json:"urls"`
	Files []string `json:"files"`
}

func (r Request) len() int {
	return len(r.Urls)
}

func (r Request) check() error {
	op := "request"
	for _, url := range r.Urls {
		u, err := urlpkg.ParseRequestURI(url)
		if err != nil {
			return err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return &CheckError{op, url, "unsupported protocol scheme"}
		}
		if u.Host == "" {
			return &CheckError{op, url, "no host"}
		}
	}
	return nil
}

type Mail struct {
	Hosts    []string `json:"hosts"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	Subject  string   `json:"subject"`
	Body     string   `json:"body"`
}

func (m Mail) len() int {
	return len(m.Hosts)
}

func (m Mail) check() error {
	op := "mail"
	validate := func(s string) error {
		if strings.ContainsAny(s, "\n\r") {
			return &CheckError{op, s, "contains CR/LF"}
		}
		return nil
	}
	if err := validate(m.From); err != nil {
		return err
	}
	for _, recp := range m.To {
		if err := validate(recp); err != nil {
			return err
		}
	}
	if m.len() > 0 {
		if m.Username == "" {
			return &CheckError{op, "", "empty username"}
		}
		if m.Password == "" {
			return &CheckError{op, "", "empty password"}
		}
		if len(m.To) == 0 {
			return &CheckError{op, nil, "no recipients"}
		}
	}
	return nil
}

func (m *Mail) prepare() {
	if m.Username == "" {
		m.Username = os.Getenv(EnvMailUsername)
	}
	if m.Password == "" {
		m.Password = os.Getenv(EnvMailPassword)
	}
	if m.From == "" {
		m.From = m.Username
	}
}

type Async struct {
	Run     Run      `json:"run"`
	Request Request  `json:"request"`
	Mail    Mail     `json:"mail"`
	Timeout Duration `json:"timeout"`
}

func (a Async) len() int {
	return a.Run.len() + a.Request.len() + a.Mail.len()
}

func (a Async) check() error {
	if err := a.Run.check(); err != nil {
		return err
	}
	if err := a.Request.check(); err != nil {
		return err
	}
	if err := a.Mail.check(); err != nil {
		return err
	}
	return nil
}

func (a *Async) prepare() {
	if a.Timeout == 0 {
		a.Timeout = DefaultTimeout
	}
	a.Run.prepare()
	a.Mail.prepare()
}

type KillError struct {
	Pid int
	Err error
}

func (e *KillError) Error() string {
	return e.Err.Error() + ": " + strconv.Itoa(e.Pid)
}

func (e *KillError) Unwrap() error {
	return e.Err
}

type Kill struct {
	Pids   []int          `json:"pids"`
	Signal syscall.Signal `json:"signal"`
}

func (k Kill) len() int {
	return len(k.Pids)
}

func (k Kill) check() error {
	for _, pid := range k.Pids {
		if err := syscall.Kill(pid, 0); err != nil {
			return &KillError{pid, err}
		}
	}
	return nil
}

func (k *Kill) prepare() {
	if k.Signal == 0 {
		k.Signal = DefaultSignal
	}
}

type Remove struct {
	Paths []string `json:"paths"`
}

func (r Remove) len() int {
	return len(r.Paths)
}

type Run struct {
	Commands   []string `json:"commands"`
	Env        []string `json:"env"`
	Executable string   `json:"executable"`
	Option     string   `json:"option"`
}

func (r Run) len() int {
	return len(r.Commands)
}

func (r *Run) prepare() {
	if r.Executable == "" {
		r.Executable = os.Getenv("SHELL")
		if r.Executable == "" {
			r.Executable = FallbackExecutable
		}
		if r.Option == "" {
			r.Option = "-c"
		}
	}
}

func (r Run) check() error {
	if err := syscall.Access(r.Executable, 0x1); err != nil {
		return &os.PathError{"access", r.Executable, err}
	}
	return nil
}

func (r Run) env() []string {
	return append(os.Environ(), r.Env...)
}

type state struct {
	sync.Mutex
	isRunning bool
	isWaiting bool
	isDone    bool
}

type Wanted struct {
	config Config
	errors chan error
	stop   chan struct{}
	state  state
}

func (w *Wanted) Check() error {
	return w.config.check()
}

func (w *Wanted) StartMonitor() bool {
	w.state.Lock()
	defer w.state.Unlock()
	if !w.state.isRunning && !w.state.isDone {
		w.state.isRunning = true
		w.state.isWaiting = true
		go w.startMonitor()
		return true
	}
	return false
}

func (w *Wanted) startMonitor() {
	threshold := max(1, w.config.Notify.Threshold)
	prethreshold := threshold - 1
	sigchan := make(chan os.Signal, threshold*2+1)
	fire := make(chan struct{})
	signal.Notify(sigchan, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGHUP)
	delay := w.config.Notify.Delay.Unwrap()
	arm := func() {
		w.state.Lock()
		if w.state.isWaiting {
			w.state.isWaiting = false
			fire <- struct{}{}
		}
		w.state.Unlock()
	}
	i := 0
	t := time.NewTimer(0)
	stop := func() {
		signal.Stop(sigchan)
		t.Stop()
	}
Loop:
	for {
		select {
		case sig := <-sigchan:
			switch sig {
			case syscall.SIGUSR1:
				i++
				if i == threshold {
					t = time.AfterFunc(delay, arm)
				}
			case syscall.SIGUSR2:
				if i > 0 {
					i--
					if i == prethreshold {
						t.Stop()
					}
				}
			case syscall.SIGHUP:
				if err := w.reconfig(); err != nil {
					log.Println("HUP:", err.Error())
				}
			}
		case <-fire:
			stop()
			break Loop
		case <-w.stop:
			stop()
			w.state.Lock()
			w.state.isRunning = false
			w.state.Unlock()
			return
		}
	}
	w.clean()
	close(w.errors)
	w.state.Lock()
	w.state.isDone = true
	w.state.isRunning = false
	w.state.Unlock()
}

func (w *Wanted) StopMonitor() bool {
	w.state.Lock()
	defer w.state.Unlock()
	if w.state.isWaiting {
		w.state.isWaiting = false
		w.stop <- struct{}{}
		return true
	}
	return false
}

func (w *Wanted) Errors() <-chan error {
	return w.errors
}

func (w *Wanted) IsDone() bool {
	w.state.Lock()
	v := w.state.isDone
	w.state.Unlock()
	return v
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
	var wg sync.WaitGroup
	w.doAsyncRun(&wg)
	w.doAsyncRequest(&wg)
	w.doAsyncMail(&wg)
	wg.Wait()
}

func (w *Wanted) doAsyncRun(wg *sync.WaitGroup) {
	n := w.config.Async.Run.len()
	if n > 0 {
		wg.Add(n)
		timeout := w.config.Async.Timeout.Unwrap()
		env := w.config.Async.Run.env()
		run := func(command string) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			cmd := exec.CommandContext(
				ctx,
				w.config.Async.Run.Executable,
				w.config.Async.Run.Option,
				command,
			)
			cmd.Env = env
			w.errors <- cmd.Run()
			cancel()
			wg.Done()
		}
		for _, command := range w.config.Async.Run.Commands {
			go run(command)
		}
	}
}

func (w *Wanted) doAsyncRequest(wg *sync.WaitGroup) {
	n := w.config.Async.Request.len()
	if n > 0 {
		wg.Add(n)
		httpClient := &http.Client{Timeout: w.config.Async.Timeout.Unwrap()}
		hasFiles := len(w.config.Async.Request.Files) > 0
		request := func(url string) {
			if hasFiles {
				postFiles(
					httpClient,
					url,
					w.config.Async.Request.Files,
					w.errors,
				)
			} else {
				if resp, err := httpClient.Get(url); err != nil {
					w.errors <- err
				} else {
					resp.Body.Close()
				}
			}
			wg.Done()
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
		timeout := w.config.Async.Timeout.Unwrap()
		addressToHeader := func(s string) string {
			return (&mailpkg.Address{"", s}).String()
		}
		to := make([]string, len(w.config.Async.Mail.To))
		for idx, addr := range w.config.Async.Mail.To {
			to[idx] = addressToHeader(addr)
		}
		message := fmt.Sprintf(
			"From: %%s\r\n"+
				"To: %s\r\n"+
				"Subject: %s\r\n"+
				"\r\n"+
				"%s\r\n",
			strings.Join(to, ", "),
			w.config.Async.Mail.Subject,
			w.config.Async.Mail.Body,
		)
		hostnameSep := "."
		addDomain := func(s, domain string) string {
			return s + "@" + domain
		}
		mail := func(host string) {
			deadline := time.Now().Add(timeout)
			defer wg.Done()
			var hostname string
			colonPos := strings.LastIndex(host, ":")
			if colonPos == -1 {
				hostname = host
				host += ":465"
			} else {
				hostname = host[:colonPos]
			}
			conn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: timeout, Deadline: deadline},
				"tcp",
				host,
				&tls.Config{ServerName: hostname},
			)
			if err != nil {
				w.errors <- err
				return
			}
			defer conn.Close()
			if err = conn.SetDeadline(deadline); err != nil {
				w.errors <- err
				return
			}
			cl, err := smtp.NewClient(conn, hostname)
			if err != nil {
				w.errors <- err
				return
			}
			hostnameParts := strings.Split(hostname, hostnameSep)
			domain := strings.Join(
				hostnameParts[max(0, len(hostnameParts)-2):],
				hostnameSep,
			)
			if err = cl.Auth(smtp.PlainAuth(
				"",
				addDomain(w.config.Async.Mail.Username, domain),
				w.config.Async.Mail.Password,
				hostname,
			)); err != nil {
				w.errors <- err
				return
			}
			from := addDomain(w.config.Async.Mail.From, domain)
			if err = cl.Mail(from); err != nil {
				w.errors <- err
				return
			}
			for _, addr := range w.config.Async.Mail.To {
				if err = cl.Rcpt(addr); err != nil {
					w.errors <- err
					return
				}
			}
			wc, err := cl.Data()
			if err != nil {
				w.errors <- err
				return
			}
			if _, err = wc.Write([]byte(fmt.Sprintf(
				message,
				addressToHeader(from),
			))); err != nil {
				w.errors <- err
				return
			}
			if err = wc.Close(); err != nil {
				w.errors <- err
				return
			}
			w.errors <- cl.Quit()
		}
		for _, host := range w.config.Async.Mail.Hosts {
			go mail(host)
		}
	}
}

func (w *Wanted) doKill() {
	for _, pid := range w.config.Kill.Pids {
		if err := syscall.Kill(pid, w.config.Kill.Signal); err != nil {
			w.errors <- &KillError{pid, err}
		}
	}
}

func (w *Wanted) doRemove() {
	for _, path := range w.config.Remove.Paths {
		w.errors <- os.RemoveAll(path)
	}
}

func (w *Wanted) doRun() {
	if w.config.Run.len() > 0 {
		env := w.config.Run.env()
		for _, command := range w.config.Run.Commands {
			cmd := exec.Command(
				w.config.Run.Executable,
				w.config.Run.Option,
				command,
			)
			cmd.Env = env
			w.errors <- cmd.Run()
		}
	}
}

func NewWanted(c Config) *Wanted {
	c.prepare()
	return &Wanted{
		config: c,
		errors: make(chan error, c.errorsCap()),
		stop:   make(chan struct{}),
	}
}

func postFiles(
	client *http.Client,
	url string,
	files []string,
	errors chan<- error,
) {
	r, w := io.Pipe()
	m := multipart.NewWriter(w)
	errs := make(chan error, 1)
	go func() {
		defer w.Close()
		upload := func(index int, filePath string) error {
			file, err := os.Open(filePath)
			if err != nil {
				errors <- err
				return nil
			}
			defer file.Close()
			part, err := m.CreateFormFile(
				"file"+strconv.Itoa(index),
				filepath.Base(file.Name()),
			)
			if err != nil {
				return err
			}
			_, err = io.Copy(part, file)
			return err
		}
		for idx, filePath := range files {
			if err := upload(idx, filePath); err != nil {
				errs <- err
				return
			}
		}
		errs <- m.Close()
	}()
	if resp, err := client.Post(url, m.FormDataContentType(), r); err != nil {
		errors <- err
	} else {
		resp.Body.Close()
		errors <- (<-errs)
	}
	r.Close()
}
