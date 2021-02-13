package wanted

import (
	"context"
	"errors"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/x13a/wanted/config"
	"github.com/x13a/wanted/monitor"
)

const Version = "0.2.1"

type cleaner struct {
	config config.Config
	count  int
}

func (c *cleaner) Wait(m monitor.Monitor) error {
	errChan := make(chan error)
	go m.Listen(errChan)
	if err := <-errChan; err != nil {
		return err
	}
	if c.Clean() > 0 {
		return errors.New("clean errors: " + strconv.Itoa(c.count))
	}
	return nil
}

func (c *cleaner) Clean() int {
	log.Println("Clean at:", time.Now().Format(time.RFC1123Z))
	errChan := make(chan error, 1<<6)
	go c.clean(errChan)
	for err := range errChan {
		if err != nil {
			c.count++
			log.Println(err)
		}
	}
	return c.count
}

func (c *cleaner) clean(errChan chan<- error) {
	defer close(errChan)
	waitChan := make(chan bool, 1)
	go c.async(waitChan, errChan)
	if !<-waitChan {
		log.Println("async timeout")
	}
	c.config.Kill.Do(errChan)
	c.config.Remove.Do(errChan)
	c.config.Run.Do(errChan)
}

func (c *cleaner) async(waitChan chan<- bool, errChan chan<- error) {
	timeout := c.config.Async.Timeout.Unwrap()
	timer := time.AfterFunc(timeout, func() { waitChan <- false })
	defer timer.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(4)
	go c.config.Async.Broadcast.AsyncDo(ctx, &wg, errChan)
	go c.config.Async.Run.AsyncDo(ctx, &wg, errChan)
	go c.config.Async.Request.AsyncDo(ctx, &wg, errChan)
	go c.config.Async.Mail.AsyncDo(ctx, &wg, errChan)
	wg.Wait()
	waitChan <- true
}

func NewCleaner(c config.Config) *cleaner {
	return &cleaner{config: c}
}

func Start(c config.Config, m monitor.Mode) error {
	if err := c.Init(); err != nil {
		return err
	}
	return NewCleaner(c).Wait(monitor.New(c, m))
}
