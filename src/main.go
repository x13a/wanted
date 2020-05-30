package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"./wanted"
)

const (
	FlagCheck   = "C"
	FlagConfig  = "c"
	FlagPidFile = "p"
	FlagRemove  = "r"
	FlagNoLog   = "n"

	ExitSuccess = 0
	ExitFailure = 1
	ExitUsage   = 2
)

type Opts struct {
	check   wanted.Config
	config  wanted.Config
	pidfile string
	remove  bool
	nolog   bool
}

func parseArgs() *Opts {
	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(ExitUsage)
	}
	opts := &Opts{}
	isHelp := flag.Bool("h", false, "Print help and exit")
	isVersion := flag.Bool("V", false, "Print version and exit")
	flag.Var(&opts.check, FlagCheck, "Check configuration file and exit")
	flag.Var(&opts.config, FlagConfig, "Path to configuration file")
	flag.StringVar(&opts.pidfile, FlagPidFile, "", "Write pid to file")
	flag.BoolVar(&opts.remove, FlagRemove, false, "Remove configuration file")
	flag.BoolVar(&opts.nolog, FlagNoLog, false, "Do not log clean errors")
	flag.Parse()
	if *isHelp {
		flag.Usage()
		os.Exit(ExitSuccess)
	}
	if *isVersion {
		fmt.Println(wanted.Version)
		os.Exit(ExitSuccess)
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
		os.Exit(ExitUsage)
	}
	return opts
}

func _main() (int, error) {
	opts := parseArgs()
	w := wanted.NewWanted(opts.config)
	if err := w.Check(); err != nil {
		return ExitFailure, err
	} else if opts.check.Path() != "" {
		return ExitSuccess, nil
	}
	pid := os.Getpid()
	if opts.pidfile != "" {
		if err := ioutil.WriteFile(
			opts.pidfile,
			[]byte(strconv.Itoa(pid)),
			0644,
		); err != nil {
			return ExitFailure, err
		}
		defer func() {
			if err := os.Remove(opts.pidfile); err != nil {
				log.Println(err)
			}
		}()
	}
	if opts.remove {
		if path := opts.config.Path(); path != wanted.ArgStdin {
			if err := os.Remove(path); err != nil {
				return ExitFailure, err
			}
		}
	}
	if os.Geteuid() != 0 {
		log.Println("[WARNING] running not root")
	}
	log.Println("pid:", pid)
	w.StartMonitor()
	exitCode := ExitSuccess
	for {
		for err := range w.Errors() {
			if err != nil {
				exitCode = ExitFailure
				if !opts.nolog {
					log.Println(err)
				}
			}
		}
		if w.IsDone() {
			break
		}
	}
	return exitCode, nil
}

func main() {
	exitCode, err := _main()
	if err != nil {
		log.Println(err)
	}
	os.Exit(exitCode)
}
