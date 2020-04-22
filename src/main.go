package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"syscall"

	cleaner "./lib"
)

const (
	FlagConfig  = "c"
	FlagPidFile = "p"
	FlagUnlink  = "u"
	FlagNoLog   = "n"

	ExOk     = 0
	ExErr    = 1
	ExArgErr = 2
)

type Opts struct {
	config  cleaner.Config
	pidfile string
	unlink  bool
	nolog   bool
}

func parseArgs() *Opts {
	opts := &Opts{}
	isHelp := flag.Bool("h", false, "Print help and exit")
	isVersion := flag.Bool("V", false, "Print version and exit")
	flag.Var(&opts.config, FlagConfig, "Path to configuration file")
	flag.StringVar(&opts.pidfile, FlagPidFile, "", "Write pid file")
	flag.BoolVar(&opts.unlink, FlagUnlink, false, "Unlink configuration file")
	flag.BoolVar(&opts.nolog, FlagNoLog, false, "Do not log clean errors")
	flag.Parse()
	if *isHelp {
		flag.Usage()
		os.Exit(ExOk)
	}
	if *isVersion {
		fmt.Println(cleaner.Version)
		os.Exit(ExOk)
	}
	if opts.config.Path() == "" {
		fmt.Fprintf(os.Stderr, "`%s` is required\n", FlagConfig)
		os.Exit(ExArgErr)
	}
	return opts
}

func main() {
	opts := parseArgs()
	c := cleaner.NewCleaner(opts.config)
	if err := c.Check(); err != nil {
		log.Fatalln(err.Error())
	}
	pid := os.Getpid()
	if opts.pidfile != "" {
		if err := ioutil.WriteFile(
			opts.pidfile,
			[]byte(strconv.Itoa(pid)),
			0644,
		); err != nil {
			log.Fatalln(err.Error())
		}
	}
	if opts.unlink {
		if path := opts.config.Path(); path != cleaner.ArgStdin {
			if err := syscall.Unlink(path); err != nil {
				log.Fatalln(err.Error())
			}
		}
	}
	if os.Geteuid() != 0 {
		log.Println("[WARNING] running not root")
	}
	log.Printf("[INFO] pid: %d\n", pid)
	c.StartMonitor()
	exitCode := ExOk
	for err := range c.Errors() {
		if err != nil {
			exitCode = ExErr
			if !opts.nolog {
				log.Println(err.Error())
			}
		}
	}
	os.Exit(exitCode)
}
