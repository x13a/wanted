package monitor

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/x13a/wanted/config"
	"github.com/x13a/wanted/utils"
)

type Mode int

const (
	ModeSignal Mode = iota
	ModeBroadcast
)

func (m *Mode) Set(s string) error {
	switch s {
	case "s", "signal":
		*m = ModeSignal
	case "b", "broadcast":
		*m = ModeBroadcast
	default:
		return fmt.Errorf("invalid mode: %q", s)
	}
	return nil
}

func (m Mode) String() string {
	return strconv.Itoa(int(m))
}

type Monitor interface {
	Listen(chan<- error)
}

type signalMonitor struct {
	Threshold int
	Delay     time.Duration
}

func (m *signalMonitor) Listen(errChan chan<- error) {
	if m.Threshold < 1 {
		m.Threshold = 1
	}
	prethreshold := m.Threshold - 1
	sigChan := make(chan os.Signal, m.Threshold<<2)
	signal.Notify(sigChan, unix.SIGUSR1, unix.SIGUSR2)
	defer signal.Stop(sigChan)
	i := 0
	timer := time.NewTimer(0)
	defer timer.Stop()
	stopChan := make(chan struct{})
	var once sync.Once
	for {
		select {
		case sig := <-sigChan:
			switch sig {
			case unix.SIGUSR1:
				i++
				if i == m.Threshold {
					timer = time.AfterFunc(m.Delay, func() {
						once.Do(func() {
							close(errChan)
							signal.Stop(sigChan)
							close(stopChan)
						})
					})
				}
			case unix.SIGUSR2:
				if i > 0 {
					i--
					if i == prethreshold {
						timer.Stop()
					}
				}
			}
		case <-stopChan:
			return
		}
	}
}

func newSignalMonitor(c *config.Config) *signalMonitor {
	return &signalMonitor{
		c.Notify.Threshold,
		c.Notify.Delay.Unwrap(),
	}
}

type broadcastMonitor struct {
	Password string
	Addr     string
}

func (m *broadcastMonitor) Listen(errChan chan<- error) {
	if m.Password == "" {
		errChan <- errors.New("empty broadcast password")
		return
	}
	addr, err := net.ResolveUDPAddr("udp4", m.Addr)
	if err != nil {
		errChan <- err
		return
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		errChan <- err
		return
	}
	defer conn.Close()
	msg := []byte(config.BroadcastMessage)
	i := 0
	for {
		buf := make([]byte, 1<<6)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Println(err)
			if i++; i == 5 {
				errChan <- errors.New("ReadFromUDP multiple errors")
				return
			}
			continue
		}
		data, err := utils.Decrypt(m.Password, buf[:n])
		if err != nil {
			log.Println(err)
			continue
		}
		if bytes.Equal(data, msg) {
			close(errChan)
			return
		}
	}
}

func newBroadcastMonitor(c *config.Config) *broadcastMonitor {
	return &broadcastMonitor{
		c.Async.Broadcast.Password,
		c.Async.Broadcast.Addr,
	}
}

func New(c config.Config, m Mode) Monitor {
	switch m {
	case ModeSignal:
		return newSignalMonitor(&c)
	case ModeBroadcast:
		return newBroadcastMonitor(&c)
	}
	return nil
}
