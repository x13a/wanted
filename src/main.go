package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	cleaner "./lib"
)

const (
	FlagCheck   = "C"
	FlagConfig  = "c"
	FlagPidFile = "p"
	FlagRemove  = "r"
	FlagNoLog   = "n"

	ExOk     = 0
	ExErr    = 1
	ExArgErr = 2
)

type Opts struct {
	check   cleaner.Config
	config  cleaner.Config
	pidfile string
	remove  bool
	nolog   bool
}

func parseArgs() *Opts {
	opts := &Opts{}
	isHelp := flag.Bool("h", false, "Print help and exit")
	isVersion := flag.Bool("V", false, "Print version and exit")
	flag.Var(&opts.check, FlagCheck, "Check configuration file and exit")
	flag.Var(&opts.config, FlagConfig, "Path to configuration file")
	flag.StringVar(&opts.pidfile, FlagPidFile, "", "Write pid file")
	flag.BoolVar(&opts.remove, FlagRemove, false, "Remove configuration file")
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
	if opts.check.Path() != "" {
		opts.config = opts.check
	} else if opts.config.Path() == "" {
		fmt.Fprintf(
			os.Stderr,
			"-{ %s | %s } required\n",
			FlagCheck,
			FlagConfig,
		)
		os.Exit(ExArgErr)
	}
	return opts
}

func main() {
	opts := parseArgs()
	c := cleaner.NewCleaner(opts.config)
	if err := c.Check(); err != nil {
		log.Fatalln(err.Error())
	} else if opts.check.Path() != "" {
		os.Exit(ExOk)
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
	if opts.remove {
		if path := opts.config.Path(); path != cleaner.ArgStdin {
			if err := os.Remove(path); err != nil {
				log.Fatalln(err.Error())
			}
		}
	}
	if os.Geteuid() != 0 {
		log.Println("[WARNING] running not root")
	}
	log.Println("pid:", pid)
	c.StartMonitor()
	exitCode := ExOk
	for {
		for err := range c.Errors() {
			if err != nil {
				exitCode = ExErr
				if !opts.nolog {
					log.Println(err.Error())
				}
			}
		}
		if c.IsDone() {
			break
		}
	}
	os.Exit(exitCode)
}
