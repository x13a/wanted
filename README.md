# cleaner

Description

## Installation
```sh
$ make
$ make install
```
or
```sh
$ brew tap x31a/tap https://bitbucket.org/x31a/homebrew-tap.git
$ brew install x31a/tap/cleaner
```

## Usage
```text
Usage of cleaner:
  -C value
    	Check configuration file and exit
  -V	Print version and exit
  -c value
    	Path to configuration file
  -h	Print help and exit
  -n	Do not log clean errors
  -p string
    	Write pid file
  -r	Remove configuration file
```

## Example

To check config and exit:
```sh
$ cleaner -C ~/cleaner.json
```

To default run:
```sh
$ cleaner -c ~/cleaner.json
```
