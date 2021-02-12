package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"github.com/x13a/wanted/config"
	"github.com/x13a/wanted/monitor"
	"github.com/x13a/wanted/wanted"
)

const (
	FlagConfig  = "c"
	FlagMode    = "m"
	FlagPidFile = "p"

	ExitSuccess = 0
	ExitUsage   = 2

	DefaultConfigPath = "/usr/local/etc/wanted.json"
)

type Opts struct {
	config  config.Config
	mode    monitor.Mode
	pidfile string
}

func getOpts() *Opts {
	opts := &Opts{}
	isVersion := flag.Bool("V", false, "Print version and exit")
	flag.Var(
		&opts.config,
		FlagConfig,
		fmt.Sprintf(
			"Path to configuration file (default: %s)",
			DefaultConfigPath,
		),
	)
	flag.Var(&opts.mode, FlagMode, "Monitor mode (default: signal)")
	flag.StringVar(&opts.pidfile, FlagPidFile, "", "Write pid to file")
	flag.Parse()
	if *isVersion {
		fmt.Println(wanted.Version)
		os.Exit(ExitSuccess)
	}
	if opts.config.Path() == "" {
		if err := opts.config.Set(DefaultConfigPath); err != nil {
			fmt.Fprintln(flag.CommandLine.Output(), err)
			os.Exit(ExitUsage)
		}
	}
	return opts
}

func _main() error {
	opts := getOpts()
	pid := os.Getpid()
	if opts.pidfile != "" {
		if err := ioutil.WriteFile(
			opts.pidfile,
			[]byte(strconv.Itoa(pid)),
			0644,
		); err != nil {
			return err
		}
		defer os.Remove(opts.pidfile)
	}
	if os.Geteuid() != 0 {
		log.Println("[WARNING] running not root")
	}
	log.Println("pid:", pid)
	return wanted.Start(opts.config, opts.mode)
}

func main() {
	if err := _main(); err != nil {
		log.Fatalln(err)
	}
}
