package config

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/x13a/wanted/email"
	"github.com/x13a/wanted/utils"
)

const (
	EnvMailUsername      = "MAIL_USERNAME"
	EnvMailPassword      = "MAIL_PASSWORD"
	EnvBroadcastPassword = "BROADCAST_PASSWORD"

	DefaultBroacastAddress = ":8989"
	DefaultAsyncTimeout    = 1 << 4 * time.Second
	DefaultKillSignal      = unix.SIGKILL
	FallbackRunExecutable  = "/bin/sh"

	BroadcastMessage = "panic"
)

type RemoveMode int

const (
	RemoveNone RemoveMode = iota
	RemoveSimple
	RemoveSecure
)

func (r *RemoveMode) UnmarshalJSON(b []byte) error {
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	switch v := RemoveMode(i); v {
	case RemoveNone, RemoveSimple, RemoveSecure:
		*r = v
		return nil
	}
	return errors.New("invalid mode: " + strconv.Itoa(i))
}

type Config struct {
	Notify Notify `json:"notify"`
	Async  Async  `json:"async"`
	Kill   Kill   `json:"kill"`
	Remove Remove `json:"remove"`
	Run    Run    `json:"run"`
	path   string
}

func (c *Config) Init() (err error) {
	if err = c.Notify.Init(); err != nil {
		return
	}
	if err = c.Async.Init(); err != nil {
		return
	}
	if err = c.Kill.Init(); err != nil {
		return
	}
	if err = c.Remove.Init(); err != nil {
		return
	}
	if err = c.Run.Init(); err != nil {
		return
	}
	c.Remove.extend(c.Async.Request.Files, c.Async.Request.Remove)
	c.Remove.extend(c.Async.Mail.Files, c.Async.Mail.Remove)
	return
}

func (c *Config) Path() string {
	return c.path
}

func (c *Config) Set(s string) error {
	var file io.ReadCloser
	var err error
	if s == "-" {
		file = os.Stdin
	} else if strings.HasPrefix(s, "https://") ||
		strings.HasPrefix(s, "http://") {

		resp, err := (&http.Client{Timeout: 1 << 4 * time.Second}).Get(s)
		if err != nil {
			return err
		}
		file = resp.Body
		defer file.Close()
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

func (c *Config) String() string {
	return ""
}

type Notify struct {
	Threshold int      `json:"threshold"`
	Delay     Duration `json:"delay"`
}

func (n *Notify) Init() error {
	if n.Threshold < 1 {
		n.Threshold = 1
	}
	return nil
}

type Broadcast struct {
	Password string `json:"password"`
	Addr     string `json:"addr"`
	Enable   bool   `json:"enable"`
}

func (b *Broadcast) Init() error {
	if b.Password == "" {
		b.Password = os.Getenv(EnvBroadcastPassword)
	}
	os.Unsetenv(EnvBroadcastPassword)
	if b.Addr == "" {
		b.Addr = DefaultBroacastAddress
	}
	if b.Enable && b.Password == "" {
		return errors.New("empty broadcast password")
	}
	return nil
}

func (b *Broadcast) AsyncDo(
	ctx context.Context,
	wg *sync.WaitGroup,
	errChan chan<- error,
) {
	defer wg.Done()
	if !b.Enable {
		return
	}
	data, err := utils.Encrypt(b.Password, []byte(BroadcastMessage))
	if err != nil {
		errChan <- err
		return
	}
	srcAddr, err := net.ResolveUDPAddr("udp4", b.Addr)
	if err != nil {
		errChan <- err
		return
	}
	port := srcAddr.Port
	srcAddr.Port = 0
	conn, err := net.ListenUDP("udp4", srcAddr)
	if err != nil {
		errChan <- err
		return
	}
	defer conn.Close()
	stopChan := make(chan struct{})
	defer close(stopChan)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stopChan:
		}
	}()
	interfaces, err := net.Interfaces()
	if err != nil {
		errChan <- err
		return
	}
	for _, iface := range interfaces {
		flags := net.FlagUp | net.FlagBroadcast
		if iface.Flags&flags != flags {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			errChan <- err
			continue
		}
		for _, addr := range addrs {
			ip := utils.AddrToBroadcastIP(addr)
			if ip == nil {
				continue
			}
			if _, err = conn.WriteToUDP(data, &net.UDPAddr{
				IP:   ip,
				Port: port,
			}); err != nil {
				errChan <- err
				if utils.IsErrNetClosing(err) {
					return
				}
			}
		}
	}
}

type Run struct {
	Commands []string `json:"commands"`
	Env      []string `json:"env"`
	Prefix   []string `json:"prefix"`
}

func (r *Run) Init() error {
	if len(r.Prefix) == 0 {
		executable := os.Getenv("SHELL")
		if executable == "" {
			executable = FallbackRunExecutable
		}
		r.Prefix = []string{executable, "-c"}
	}
	return nil
}

func (r *Run) AsyncDo(
	ctx context.Context,
	wg *sync.WaitGroup,
	errChan chan<- error,
) {
	defer wg.Done()
	if len(r.Commands) == 0 {
		return
	}
	var wg1 sync.WaitGroup
	for _, command := range r.Commands {
		wg1.Add(1)
		go r.run(ctx, &wg1, command, errChan)
	}
	wg1.Wait()
}

func (r *Run) run(
	ctx context.Context,
	wg *sync.WaitGroup,
	command string,
	errChan chan<- error,
) {
	defer wg.Done()
	args := r.args()
	args[len(args)-1] = command
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = r.env()
	if err := cmd.Run(); err != nil {
		errChan <- err
	}
}

func (r *Run) Do(errChan chan<- error) {
	if len(r.Commands) == 0 {
		return
	}
	args := r.args()
	idx := len(args) - 1
	env := r.env()
	for _, command := range r.Commands {
		args[idx] = command
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Env = env
		if err := cmd.Run(); err != nil {
			errChan <- err
		}
	}
}

func (r *Run) args() []string {
	args := make([]string, len(r.Prefix)+1)
	copy(args, r.Prefix)
	return args
}

func (r *Run) env() []string {
	return append(os.Environ(), r.Env...)
}

type Request struct {
	Urls     []string   `json:"urls"`
	Files    []string   `json:"files"`
	Headers  []string   `json:"headers"`
	Compress bool       `json:"compress"`
	Remove   RemoveMode `json:"remove"`
}

func (r *Request) Init() error {
	r.Files = extendDirFiles(r.Files)
	return nil
}

func (r *Request) AsyncDo(
	ctx context.Context,
	wg *sync.WaitGroup,
	errChan chan<- error,
) {
	defer wg.Done()
	if len(r.Urls) == 0 {
		return
	}
	var wg1 sync.WaitGroup
	httpClient := &http.Client{}
	hasFiles := len(r.Files) != 0
	for _, url := range r.Urls {
		wg1.Add(1)
		if hasFiles {
			go r.post(ctx, &wg1, url, httpClient, errChan)
		} else {
			go r.get(ctx, &wg1, url, httpClient, errChan)
		}
	}
	wg1.Wait()
}

func (r *Request) get(
	ctx context.Context,
	wg *sync.WaitGroup,
	url string,
	httpClient *http.Client,
	errChan chan<- error,
) {
	defer wg.Done()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		errChan <- err
		return
	}
	r.addHeaders(req)
	if resp, err := httpClient.Do(req); err != nil {
		errChan <- err
	} else {
		resp.Body.Close()
	}
}

func (r *Request) post(
	ctx context.Context,
	wg *sync.WaitGroup,
	url string,
	httpClient *http.Client,
	errChan chan<- error,
) {
	defer wg.Done()
	pr, pw := io.Pipe()
	defer pr.Close()
	mw := multipart.NewWriter(pw)
	go func() {
		defer pw.Close()
		upload := func(index int, path string) error {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			part, err := mw.CreateFormFile(
				"file"+strconv.Itoa(index),
				filepath.Base(file.Name()),
			)
			if err != nil {
				return err
			}
			if r.Compress {
				compressor := gzip.NewWriter(part)
				if _, err = io.Copy(compressor, file); err != nil {
					return err
				}
				return compressor.Close()
			}
			_, err = io.Copy(part, file)
			return err
		}
		for idx, path := range r.Files {
			if err := upload(idx, path); err != nil {
				errChan <- err
				if err == io.ErrClosedPipe {
					return
				}
			}
		}
		if err := mw.Close(); err != nil {
			errChan <- err
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, pr)
	if err != nil {
		errChan <- err
		return
	}
	r.addHeaders(req)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if resp, err := httpClient.Do(req); err != nil {
		errChan <- err
	} else {
		resp.Body.Close()
	}
}

func (r *Request) addHeaders(req *http.Request) {
	for _, value := range r.Headers {
		header := strings.SplitN(value, ":", 2)
		if len(header) != 2 {
			continue
		}
		req.Header.Add(header[0], header[1])
	}
}

type Mail struct {
	Hosts    []string   `json:"hosts"`
	Username string     `json:"username"`
	Password string     `json:"password"`
	From     string     `json:"from"`
	To       []string   `json:"to"`
	Subject  string     `json:"subject"`
	Body     string     `json:"body"`
	Files    []string   `json:"files"`
	Compress bool       `json:"compress"`
	Remove   RemoveMode `json:"remove"`
}

func (m *Mail) Init() error {
	if m.Username == "" {
		m.Username = os.Getenv(EnvMailUsername)
	}
	os.Unsetenv(EnvMailUsername)
	if m.Password == "" {
		m.Password = os.Getenv(EnvMailPassword)
	}
	os.Unsetenv(EnvMailPassword)
	if m.From == "" {
		m.From = m.Username
	}
	m.Files = extendDirFiles(m.Files)
	return nil
}

func (m *Mail) AsyncDo(
	ctx context.Context,
	wg *sync.WaitGroup,
	errChan chan<- error,
) {
	defer wg.Done()
	if len(m.Hosts) == 0 {
		return
	}
	var wg1 sync.WaitGroup
	for _, host := range m.Hosts {
		wg1.Add(1)
		go m.send(ctx, &wg1, host, errChan)
	}
	wg1.Wait()
}

func (m *Mail) send(
	ctx context.Context,
	wg *sync.WaitGroup,
	host string,
	errChan chan<- error,
) {
	defer wg.Done()
	msg := email.Message{}
	for _, to := range m.To {
		msg.AddTo("", to)
	}
	msg.Subject = m.Subject
	msg.Body = m.Body
	for _, path := range m.Files {
		// TODO do not read attachment to memory
		msg.AddAttachment(path, m.Compress)
	}
	from := m.From
	username := m.Username
	hostname := utils.HostToHostname(host)
	if len(m.Hosts) > 1 {
		domain := utils.HostnameToDomain(hostname)
		from += "@" + domain
		username += "@" + domain
	}
	msg.SetFrom("", from)
	if err := email.SendMailTLS(
		ctx,
		host,
		smtp.PlainAuth("", username, m.Password, hostname),
		msg,
	); err != nil {
		errChan <- err
	}
}

type Async struct {
	Broadcast Broadcast `json:"broadcast"`
	Run       Run       `json:"run"`
	Request   Request   `json:"request"`
	Mail      Mail      `json:"mail"`
	Timeout   Duration  `json:"timeout"`
}

func (a *Async) Init() (err error) {
	if err = a.Broadcast.Init(); err != nil {
		return
	}
	if err = a.Run.Init(); err != nil {
		return
	}
	if err = a.Request.Init(); err != nil {
		return
	}
	if err = a.Mail.Init(); err != nil {
		return
	}
	if a.Timeout == 0 {
		a.Timeout = Duration(DefaultAsyncTimeout)
	}
	return
}

type Kill struct {
	Pids     []int       `json:"pids"`
	PidFiles []string    `json:"pidfiles"`
	Signal   unix.Signal `json:"signal"`
}

func (k *Kill) Init() error {
	if k.Signal == 0 {
		k.Signal = DefaultKillSignal
	}
	k.PidFiles = extendDirFiles(k.PidFiles)
	return nil
}

func (k *Kill) Do(errChan chan<- error) {
	for _, pid := range k.Pids {
		k.kill(pid, errChan)
	}
	for _, path := range k.PidFiles {
		content, err := ioutil.ReadFile(path)
		if err != nil {
			errChan <- err
			continue
		}
		pid, err := strconv.Atoi(string(bytes.TrimSpace(content)))
		if err != nil {
			errChan <- err
			continue
		}
		k.kill(pid, errChan)
	}
}

func (k *Kill) kill(pid int, errChan chan<- error) {
	if err := unix.Kill(pid, k.Signal); err != nil {
		errChan <- err
	}
}

type Remove struct {
	FilesSecure []string `json:"files_secure"`
	Paths       []string `json:"paths"`
}

func (r *Remove) Init() error {
	r.FilesSecure = extendDirFiles(r.FilesSecure)
	return nil
}

func (r *Remove) Do(errChan chan<- error) {
	for _, path := range r.FilesSecure {
		if err := utils.Srm(path, true); err != nil {
			errChan <- err
		}
	}
	for _, path := range r.Paths {
		if err := os.RemoveAll(path); err != nil {
			errChan <- err
		}
	}
}

func (r *Remove) extend(paths []string, mode RemoveMode) {
	switch mode {
	case RemoveSimple:
		r.Paths = append(r.Paths, paths...)
	case RemoveSecure:
		r.FilesSecure = append(r.FilesSecure, paths...)
	}
}

type Duration time.Duration

func (d *Duration) Set(s string) error {
	if s == "" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return d.Set(s)
}

func (d Duration) Unwrap() time.Duration {
	return time.Duration(d)
}

func extendDirFiles(paths []string) []string {
	files := make([]string, 0, len(paths))
	for _, path := range paths {
		fileInfo, err := os.Stat(path)
		if err != nil || !fileInfo.IsDir() {
			files = append(files, path)
			continue
		}
		dir, err := ioutil.ReadDir(path)
		if err != nil {
			continue
		}
		for _, fileInfo = range dir {
			if fileInfo.IsDir() {
				continue
			}
			name := fileInfo.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			files = append(files, filepath.Join(path, name))
		}
	}
	return files
}
