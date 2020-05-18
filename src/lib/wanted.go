package wanted

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
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
	Version = "0.0.10"

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
	return c.len() + len(c.Async.Request.Files)*c.Async.Request.len() +
		len(c.Async.Mail.Files)
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

func extendDirFiles(v []string) []string {
	files := make([]string, 0, len(v))
	for _, path := range v {
		fi, err := os.Stat(path)
		if err != nil || !fi.IsDir() {
			files = append(files, path)
			continue
		}
		flist, err := ioutil.ReadDir(path)
		if err != nil {
			continue
		}
		for _, fi = range flist {
			if fi.IsDir() {
				continue
			}
			name := fi.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			files = append(files, filepath.Join(path, name))
		}
	}
	return files
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

func (r *Request) prepare() {
	if len(r.Files) > 0 {
		r.Files = extendDirFiles(r.Files)
	}
}

type Mail struct {
	Hosts    []string `json:"hosts"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	Subject  string   `json:"subject"`
	Body     string   `json:"body"`
	Files    []string `json:"files"`
}

func (m Mail) len() int {
	return len(m.Hosts)
}

func (m Mail) check() error {
	op := "mail"
	validate := func(s string) error {
		if strings.ContainsAny(s, emailNewLine) {
			return &CheckError{op, s, "contains CR/LF"}
		}
		return nil
	}
	if err := validate(m.From); err != nil {
		return err
	}
	for _, rcpt := range m.To {
		if err := validate(rcpt); err != nil {
			return err
		}
	}
	if err := validate(m.Subject); err != nil {
		return err
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
	if len(m.Files) > 0 {
		m.Files = extendDirFiles(m.Files)
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
	a.Request.prepare()
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
					log.Println("HUP:", err)
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
					true,
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
		isMultihost := n > 1
		timeout := w.config.Async.Timeout.Unwrap()
		msg := emailMessage{}
		for _, to := range w.config.Async.Mail.To {
			msg.AddTo("", to)
		}
		msg.Subject = w.config.Async.Mail.Subject
		msg.Body = w.config.Async.Mail.Body
		for _, filePath := range w.config.Async.Mail.Files {
			if err := msg.AddAttachment(filePath); err != nil {
				w.errors <- err
			}
		}
		addDomain := func(s, domain string) string {
			return s + "@" + domain
		}
		mail := func(host string) {
			deadline := time.Now().Add(timeout)
			msg1 := msg
			from := w.config.Async.Mail.From
			username := w.config.Async.Mail.Username
			hostname := getHostnameFromHost(host)
			if isMultihost {
				domain := getDomainFromHostname(hostname)
				from = addDomain(from, domain)
				username = addDomain(username, domain)
			}
			msg1.SetFrom("", from)
			if err := sendMailTLS(
				host,
				smtp.PlainAuth(
					"",
					username,
					w.config.Async.Mail.Password,
					hostname,
				),
				&msg1,
				timeout,
				deadline,
			); err != nil {
				w.errors <- err
			}
			wg.Done()
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
