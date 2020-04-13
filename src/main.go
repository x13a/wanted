package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	cleaner "./lib"
)

const (
	FlagConfig = "c"
	FlagUnlink = "u"

	ExOk     = 0
	ExArgErr = 2

	ArgStdin = "-"
)

type (
	Signal  cleaner.Signal
	Timeout time.Duration
)

func (s *Signal) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	str = strings.ToUpper(str)
	var sig cleaner.Signal
	switch str {
	case "USR", "USR1", "SIGUSR", "SIGUSR1":
		sig = cleaner.SIGUSR1
	case "USR2", "SIGUSR2":
		sig = cleaner.SIGUSR2
	default:
		return errors.New("signal parse error")
	}
	*s = Signal(sig)
	return nil
}

func (s Signal) unwrap() cleaner.Signal {
	return cleaner.Signal(s)
}

func (t *Timeout) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*t = Timeout(v)
	return nil
}

func (t Timeout) unwrap() time.Duration {
	return time.Duration(t)
}

type Config struct {
	Signal  Signal `json:"signal"`
	Request struct {
		Urls    []string `json:"urls"`
		Timeout *Timeout `json:"timeout"`
	} `json:"request"`
	Kill     cleaner.Kill `json:"kill"`
	Paths    []string     `json:"paths"`
	Commands []string     `json:"commands"`
	path     string
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

type Opts struct {
	config Config
	unlink bool
}

func parseArgs() *Opts {
	opts := &Opts{}
	isHelp := flag.Bool("h", false, "Print help and exit")
	isVersion := flag.Bool("V", false, "Print version and exit")
	flag.Var(&opts.config, FlagConfig, "Path to the configuration file")
	flag.BoolVar(&opts.unlink, FlagUnlink, false, "Unlink configuration file")
	flag.Parse()
	if *isHelp {
		flag.Usage()
		os.Exit(ExOk)
	}
	if *isVersion {
		fmt.Println(cleaner.Version)
		os.Exit(ExOk)
	}
	if opts.config.path == "" {
		fmt.Fprintf(os.Stderr, "`%s` is required\n", FlagConfig)
		os.Exit(ExArgErr)
	}
	return opts
}

func main() {
	opts := parseArgs()
	if opts.unlink && opts.config.path != ArgStdin {
		syscall.Unlink(opts.config.path)
	}
	timeout := time.Duration(-1)
	if opts.config.Request.Timeout != nil {
		timeout = opts.config.Request.Timeout.unwrap()
	}
	cleaner.NewCleaner(
		opts.config.Signal.unwrap(),
		cleaner.NewRequest(opts.config.Request.Urls, timeout),
		cleaner.NewKill(opts.config.Kill.Uids, opts.config.Kill.Signal),
		opts.config.Paths,
		opts.config.Commands,
	).Run()
}
