package cleaner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	urlpkg "net/url"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	Version  = "0.0.4"
	ArgStdin = "-"

	_X_OK = 0x1
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
	if err := json.NewDecoder(file).Decode(c); err != nil {
		return err
	}
	c.path = s
	return nil
}

func (c *Config) prepare() {
	if c.Async.Timeout == 0 {
		c.Async.Timeout = Duration(1 << 4 * time.Second)
	}
	if c.Kill.Signal == 0 {
		c.Kill.Signal = syscall.SIGKILL
	}
	c.Async.Run.prepare()
	c.Run.prepare()
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
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
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

type UrlError struct {
	Url         string
	Description string
}

func (e *UrlError) Error() string {
	return fmt.Sprintf("%s: %s", e.Description, e.Url)
}

type Request struct {
	Urls []string `json:"urls"`
}

func (r Request) len() int {
	return len(r.Urls)
}

func (r Request) check() error {
	for _, url := range r.Urls {
		u, err := urlpkg.Parse(url)
		if err != nil {
			return err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return &UrlError{url, "unsupported protocol scheme"}
		}
		if u.Host == "" {
			return &UrlError{url, "http: no Host in request URL"}
		}
	}
	return nil
}

type Async struct {
	Run     Run      `json:"run"`
	Request Request  `json:"request"`
	Timeout Duration `json:"timeout"`
}

func (a Async) len() int {
	return a.Run.len() + a.Request.len()
}

func (a Async) check() error {
	if err := a.Run.check(); err != nil {
		return err
	}
	if err := a.Request.check(); err != nil {
		return err
	}
	return nil
}

type KillError struct {
	Pid int
	Err error
}

func (e *KillError) Error() string {
	return fmt.Sprintf("%s: %d", e.Err.Error(), e.Pid)
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
			r.Executable = "/bin/sh"
		}
		if r.Option == "" {
			r.Option = "-c"
		}
	}
}

func (r Run) check() error {
	if err := syscall.Access(r.Executable, _X_OK); err != nil {
		return &os.PathError{"access", r.Executable, err}
	}
	return nil
}

func max(v ...int) int {
	res := v[0]
	for _, i := range v[1:] {
		if i > res {
			res = i
		}
	}
	return res
}

type state struct {
	sync.Mutex
	isRunning bool
	isWaiting bool
	isDone    bool
}

type Cleaner struct {
	config Config
	errors chan error
	stop   chan struct{}
	state  state
}

func (c *Cleaner) StartMonitor() bool {
	c.state.Lock()
	defer c.state.Unlock()
	if !c.state.isRunning && !c.state.isDone {
		c.state.isRunning = true
		c.state.isWaiting = true
		go c.startMonitor()
		return true
	}
	return false
}

func (c *Cleaner) startMonitor() {
	threshold := max(1, c.config.Notify.Threshold)
	prethreshold := threshold - 1
	sigchan := make(chan os.Signal, threshold*2+1)
	fire := make(chan struct{})
	signal.Notify(sigchan, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGHUP)
	delay := c.config.Notify.Delay.Unwrap()
	arm := func(ctx context.Context) {
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
			c.state.Lock()
			if c.state.isWaiting {
				c.state.isWaiting = false
				fire <- struct{}{}
			}
			c.state.Unlock()
		}
	}
	i := 0
	var ctx context.Context
	var cancel context.CancelFunc = func() {}
	stop := func() {
		signal.Stop(sigchan)
		cancel()
	}
Loop:
	for {
		select {
		case sig := <-sigchan:
			switch sig {
			case syscall.SIGUSR1:
				i++
				if i == threshold {
					ctx, cancel = context.WithCancel(context.Background())
					go arm(ctx)
				}
			case syscall.SIGUSR2:
				if i > 0 {
					i--
					if i == prethreshold {
						cancel()
					}
				}
			case syscall.SIGHUP:
				if err := c.reconfig(); err != nil {
					log.Println(err.Error())
				} else {
					log.Println("[INFO] reload config success")
				}
			}
		case <-fire:
			stop()
			break Loop
		case <-c.stop:
			stop()
			c.state.Lock()
			c.state.isRunning = false
			c.state.Unlock()
			return
		}
	}
	c.clean()
	close(c.errors)
	c.state.Lock()
	c.state.isDone = true
	c.state.isRunning = false
	c.state.Unlock()
}

func (c *Cleaner) StopMonitor() bool {
	c.state.Lock()
	defer c.state.Unlock()
	if c.state.isWaiting {
		c.state.isWaiting = false
		c.stop <- struct{}{}
		return true
	}
	return false
}

func (c *Cleaner) IsDone() bool {
	c.state.Lock()
	v := c.state.isDone
	c.state.Unlock()
	return v
}

func (c *Cleaner) reconfig() error {
	var config Config
	if err := config.Set(c.config.path); err != nil {
		return err
	}
	config.prepare()
	if err := config.check(); err != nil {
		return err
	}
	c.config = config
	return nil
}

func (c *Cleaner) Errors() <-chan error {
	return c.errors
}

func (c *Cleaner) Check() error {
	return c.config.check()
}

func (c *Cleaner) clean() {
	c.doAsync()
	c.doKill()
	c.doRemove()
	c.doRun()
}

func (c *Cleaner) doAsync() {
	var wg sync.WaitGroup
	c.doAsyncRun(&wg)
	c.doAsyncRequest(&wg)
	wg.Wait()
}

func (c *Cleaner) doAsyncRun(wg *sync.WaitGroup) {
	n := c.config.Async.Run.len()
	if n > 0 {
		wg.Add(n)
		timeout := c.config.Async.Timeout.Unwrap()
		env := append(os.Environ(), c.config.Async.Run.Env...)
		run := func(command string) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			cmd := exec.CommandContext(
				ctx,
				c.config.Async.Run.Executable,
				c.config.Async.Run.Option,
				command,
			)
			cmd.Env = env
			c.errors <- cmd.Run()
			cancel()
			wg.Done()
		}
		for _, command := range c.config.Async.Run.Commands {
			go run(command)
		}
	}
}

func (c *Cleaner) doAsyncRequest(wg *sync.WaitGroup) {
	n := c.config.Async.Request.len()
	if n > 0 {
		wg.Add(n)
		httpClient := &http.Client{Timeout: c.config.Async.Timeout.Unwrap()}
		request := func(url string) {
			if resp, err := httpClient.Get(url); err == nil {
				resp.Body.Close()
			} else {
				c.errors <- err
			}
			wg.Done()
		}
		for _, url := range c.config.Async.Request.Urls {
			go request(url)
		}
	}
}

func (c *Cleaner) doKill() {
	for _, pid := range c.config.Kill.Pids {
		if err := syscall.Kill(pid, c.config.Kill.Signal); err != nil {
			c.errors <- &KillError{pid, err}
		}
	}
}

func (c *Cleaner) doRemove() {
	for _, path := range c.config.Remove.Paths {
		c.errors <- os.RemoveAll(path)
	}
}

func (c *Cleaner) doRun() {
	if c.config.Run.len() > 0 {
		env := append(os.Environ(), c.config.Run.Env...)
		for _, command := range c.config.Run.Commands {
			cmd := exec.Command(
				c.config.Run.Executable,
				c.config.Run.Option,
				command,
			)
			cmd.Env = env
			c.errors <- cmd.Run()
		}
	}
}

func NewCleaner(c Config) *Cleaner {
	c.prepare()
	return &Cleaner{
		config: c,
		errors: make(
			chan error,
			c.Async.len()+c.Kill.len()+c.Remove.len()+c.Run.len(),
		),
		stop: make(chan struct{}),
	}
}
