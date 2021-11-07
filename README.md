# wanted

Run panic tasks on signal or broadcast receive.

Listen for signals:
- *USR1* to increment counter
- *USR2* to decrement counter

When counter equals threshold, run "arm" goroutine which waits for delay, 
if while delay counter become below threshold stop "arm" goroutine, else do 
clean and exit.

Broadcast receiver doesn't use counter.

Clean order:
- *Async* (*Broadcast*, *Run*, *Request*, *Mail*)
- *Kill*
- *Remove*
- *Run*

*Async* tasks has timeout, default to *16s*, and run concurrently.

## Installation
```sh
$ make
$ sudo make install
```

## Usage
```text
Usage of wanted:
  -V	Print version and exit
  -c value
    	Path to configuration file (default: /usr/local/etc/wanted.json)
  -m	Monitor mode (default: signal)
  -p string
    	Write pid to file
```

## Example

To run with custom config filepath as signal receiver:
```sh
$ wanted -c ~/wanted.json
```

To run with default config filepath as broadcast receiver:
```sh
$ wanted -m broadcast
```
