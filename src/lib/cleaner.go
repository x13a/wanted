package cleaner

import (
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type Signal syscall.Signal

func (s Signal) Unwrap() syscall.Signal {
	return syscall.Signal(s)
}

const (
	Version = "0.0.1"

	SIGUSR1 = Signal(syscall.SIGUSR1)
	SIGUSR2 = Signal(syscall.SIGUSR2)
)

type Request struct {
	Urls    []string
	Timeout time.Duration
}

type Kill struct {
	Uids   []int          `json:"uids"`
	Signal syscall.Signal `json:"signal"`
}

type Cleaner struct {
	signal   Signal
	request  Request
	kill     Kill
	paths    []string
	commands []string
}

func (c *Cleaner) Run() {
	c.check()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, c.signal.Unwrap())
	<-ch
	c.clean()
}

func (c *Cleaner) check() {
	if os.Geteuid() != 0 {
		log.Println("[WARNING] running not root")
	}
}

func (c *Cleaner) clean() {
	var wg sync.WaitGroup
	urlsLen := len(c.request.Urls)
	if urlsLen > 0 {
		wg.Add(urlsLen)
		httpClient := &http.Client{Timeout: c.request.Timeout}
		get := func(url string) {
			if resp, err := httpClient.Get(url); err == nil {
				resp.Body.Close()
			}
			wg.Done()
		}
		for _, url := range c.request.Urls {
			go get(url)
		}
	}
	for _, uid := range c.kill.Uids {
		syscall.Kill(uid, c.kill.Signal)
	}
	for _, path := range c.paths {
		os.RemoveAll(path)
	}
	for _, command := range c.commands {
		exec.Command("/bin/sh", "-c", command).Run()
	}
	wg.Wait()
}

func NewRequest(urls []string, timeout time.Duration) Request {
	if timeout < 0 {
		timeout = 10 * time.Second
	}
	return Request{Urls: urls, Timeout: timeout}
}

func NewKill(uids []int, signal syscall.Signal) Kill {
	if signal < 1 {
		signal = syscall.SIGKILL
	}
	return Kill{Uids: uids, Signal: signal}
}

func NewCleaner(
	signal Signal,
	request Request,
	kill Kill,
	paths []string,
	commands []string,
) *Cleaner {
	if signal < 1 {
		signal = SIGUSR1
	}
	return &Cleaner{
		signal:   signal,
		request:  request,
		kill:     kill,
		paths:    paths,
		commands: commands,
	}
}
