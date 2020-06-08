package wanted

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	urlpkg "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	envPrefix            = "WANTED_"
	EnvMailUsername      = envPrefix + "MAIL_USERNAME"
	EnvMailPassword      = envPrefix + "MAIL_PASSWORD"
	EnvBroadcastPassword = envPrefix + "BROADCAST_PASSWORD"

	DefaultBroacastAddress = ":8989"
	DefaultAsyncTimeout    = 1 << 4 * time.Second
	DefaultAsyncDelay      = 1 << 1 * time.Second
	DefaultKillSignal      = syscall.SIGKILL
	FallbackRunExecutable  = "/bin/sh"
)

type Config struct {
	Notify Notify `json:"notify"`
	Async  Async  `json:"async"`
	Kill   Kill   `json:"kill"`
	Remove Remove `json:"remove"`
	Run    Run    `json:"run"`
	path   string
}

func (c *Config) Path() string {
	return c.path
}

func (c *Config) String() string {
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
	c.Notify.prepare()
	c.Async.prepare()
	c.Kill.prepare()
	c.Run.prepare()
	if *c.Async.Request.Remove {
		c.Remove.Paths = append(c.Remove.Paths, c.Async.Request.Files...)
	}
	if *c.Async.Mail.Remove {
		c.Remove.Paths = append(c.Remove.Paths, c.Async.Mail.Files...)
	}
	if *c.Kill.Remove {
		c.Remove.Paths = append(c.Remove.Paths, c.Kill.PidFiles...)
	}
}

func (c *Config) len() int {
	return c.Async.len() + c.Kill.len() + c.Remove.len() + c.Run.len()
}

func (c *Config) errorsCap() int {
	return c.len() + c.Async.errorsCap()
}

func (c *Config) check() error {
	if err := c.Async.check(); err != nil {
		return err
	}
	if err := c.Kill.check(); err != nil {
		return err
	}
	if err := c.Remove.check(); err != nil {
		return err
	}
	if err := c.Run.check(); err != nil {
		return err
	}
	return nil
}

type Notify struct {
	Threshold int      `json:"threshold"`
	Delay     Duration `json:"delay"`
}

func (n *Notify) prepare() {
	if n.Threshold < 1 {
		n.Threshold = 1
	}
}

type Broadcast struct {
	Password string `json:"password"`
	Addr     string `json:"addr"`
	Ignore   *bool  `json:"ignore"`
}

func (b *Broadcast) len() int {
	if *b.Ignore || b.Password == "" {
		return 0
	}
	return 1
}

func (b *Broadcast) check() error {
	if _, err := net.ResolveUDPAddr("udp4", b.Addr); err != nil {
		return err
	}
	return nil
}

func (b *Broadcast) prepare() {
	if b.Password == "" {
		b.Password = os.Getenv(EnvBroadcastPassword)
	}
	if b.Addr == "" {
		b.Addr = DefaultBroacastAddress
	}
	if b.Ignore == nil {
		setBoolRef(&b.Ignore, false)
	}
}

func (b *Broadcast) errorsCap() int {
	return 21
}

type Request struct {
	Urls     []string `json:"urls"`
	Files    []string `json:"files"`
	Compress *bool    `json:"compress"`
	Remove   *bool    `json:"remove"`
}

func (r *Request) len() int {
	return len(r.Urls)
}

func (r *Request) check() error {
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
	for _, path := range r.Files {
		if _, err := os.Stat(path); err != nil {
			log.Println(err)
		}
	}
	return nil
}

func (r *Request) prepare() {
	if len(r.Files) != 0 {
		r.Files = extendDirFiles(r.Files)
	}
	if r.Compress == nil {
		setBoolRef(&r.Compress, true)
	}
	if r.Remove == nil {
		setBoolRef(&r.Remove, true)
	}
}

func (r *Request) errorsCap() int {
	return r.len() * r.errorsCapPerItem()
}

func (r *Request) errorsCapPerItem() int {
	return len(r.Files) + 1
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
	Compress *bool    `json:"compress"`
	Remove   *bool    `json:"remove"`
}

func (m *Mail) len() int {
	return len(m.Hosts)
}

func (m *Mail) check() error {
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
	if m.len() != 0 {
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
	var totalSize int64
	for _, path := range m.Files {
		if fileinfo, err := os.Stat(path); err != nil {
			log.Println(err)
		} else {
			totalSize += fileinfo.Size()
		}
	}
	if totalSize > 1<<24 {
		log.Printf("email files size sum: %dM\n", totalSize/(1<<20))
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
	if len(m.Files) != 0 {
		m.Files = extendDirFiles(m.Files)
	}
	if m.Compress == nil {
		setBoolRef(&m.Compress, true)
	}
	if m.Remove == nil {
		setBoolRef(&m.Remove, true)
	}
}

func (m *Mail) errorsCap() int {
	return len(m.Files)
}

type Async struct {
	Broadcast Broadcast `json:"broadcast"`
	Run       Run       `json:"run"`
	Request   Request   `json:"request"`
	Mail      Mail      `json:"mail"`
	Timeout   Duration  `json:"timeout"`
	Delay     Duration  `json:"delay"`
}

func (a *Async) len() int {
	return a.Broadcast.len() + a.Run.len() + a.Request.len() + a.Mail.len() + 1
}

func (a *Async) check() error {
	if err := a.Broadcast.check(); err != nil {
		return err
	}
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
	a.Broadcast.prepare()
	a.Run.prepare()
	a.Request.prepare()
	a.Mail.prepare()
	if a.Timeout == 0 {
		a.Timeout = Duration(DefaultAsyncTimeout)
	}
	if a.Delay == 0 {
		a.Delay = Duration(DefaultAsyncDelay)
	}
}

func (a *Async) errorsCap() int {
	return a.Broadcast.errorsCap() + a.Request.errorsCap() + a.Mail.errorsCap()
}

type Kill struct {
	Pids     []int          `json:"pids"`
	PidFiles []string       `json:"pidfiles"`
	Signal   syscall.Signal `json:"signal"`
	Remove   *bool          `json:"remove"`
}

func (k *Kill) len() int {
	return len(k.Pids) + len(k.PidFiles)
}

func (k *Kill) check() error {
	for _, pid := range k.Pids {
		if err := syscall.Kill(pid, 0); err != nil {
			return &KillError{pid, err}
		}
	}
	for _, path := range k.PidFiles {
		if _, err := os.Stat(path); err != nil {
			log.Println(err)
		}
	}
	return nil
}

func (k *Kill) prepare() {
	if len(k.PidFiles) != 0 {
		k.PidFiles = extendDirFiles(k.PidFiles)
	}
	if k.Signal == 0 {
		k.Signal = DefaultKillSignal
	}
	if k.Remove == nil {
		setBoolRef(&k.Remove, true)
	}
}

type Remove struct {
	Paths []string `json:"paths"`
}

func (r *Remove) len() int {
	return len(r.Paths)
}

func (r *Remove) check() error {
	for _, path := range r.Paths {
		if _, err := os.Stat(path); err != nil {
			log.Println(err)
		}
	}
	return nil
}

type Run struct {
	Commands []string `json:"commands"`
	Env      []string `json:"env"`
	Prefix   []string `json:"prefix"`
}

func (r *Run) len() int {
	return len(r.Commands)
}

func (r *Run) prepare() {
	if len(r.Prefix) == 0 {
		executable := os.Getenv("SHELL")
		if executable == "" {
			executable = FallbackRunExecutable
		}
		r.Prefix = []string{executable, "-c"}
	}
}

func (r *Run) check() error {
	executable := r.Prefix[0]
	if err := syscall.Access(executable, 0x1); err != nil {
		return &os.PathError{"access", executable, err}
	}
	return nil
}

func (r *Run) args() []string {
	prefix := r.Prefix
	args := make([]string, len(prefix)+1)
	copy(args, prefix)
	return args
}

func (r *Run) env() []string {
	return append(os.Environ(), r.Env...)
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

type CheckError struct {
	Op          string
	Value       interface{}
	Description string
}

func (e *CheckError) Error() string {
	return fmt.Sprintf("%s > %s: %v", e.Op, e.Description, e.Value)
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

func extendDirFiles(v []string) []string {
	files := make([]string, 0, len(v))
	for _, path := range v {
		fileinfo, err := os.Stat(path)
		if err != nil || !fileinfo.IsDir() {
			files = append(files, path)
			continue
		}
		dir, err := ioutil.ReadDir(path)
		if err != nil {
			continue
		}
		for _, fileinfo = range dir {
			if fileinfo.IsDir() {
				continue
			}
			name := fileinfo.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			files = append(files, filepath.Join(path, name))
		}
	}
	return files
}

func setBoolRef(b **bool, v bool) {
	*b = &v
}
