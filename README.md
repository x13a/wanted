# wanted

Run predefined tasks on signal receive.

Listen for signals:
- *USR1* to increment counter
- *USR2* to decrement counter
- *HUP*  to hot reload config

When counter equals threshold, run "arm" goroutine which waits for delay, 
if while this delay counter become below threshold stop "arm" goroutine, 
else do cleanup and exit. While waiting for "fire" config can be hot reloaded.

Cleanup order:
- *Async* (*Run*, *Request*, *Mail*)
- *Kill*
- *Remove*
- *Run*

All *Async* tasks has timeout, default to *16s*, and run in parallel.
*Run* is a list of shell commands, by default prefixed with `$SHELL -c`.

## Installation
```sh
$ make
$ make install
```
or
```sh
$ brew tap x31a/tap https://bitbucket.org/x31a/homebrew-tap.git
$ brew install x31a/tap/wanted
```

## Usage
```text
Usage of wanted:
  -C value
    	Check configuration file and exit
  -V	Print version and exit
  -c value
    	Path to configuration file
  -h	Print help and exit
  -n	Do not log clean errors
  -p string
    	Write pid to file
  -r	Remove configuration file
```

## Example

To check config and exit:
```sh
$ wanted -C /usr/local/etc/wanted.json
```

To run with config:
```sh
$ wanted -c /usr/local/etc/wanted.json
```
