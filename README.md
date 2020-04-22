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
  -V	Print version and exit
  -c value
    	Path to the configuration file
  -h	Print help and exit
  -n	Do not log clean errors
  -p string
    	Write pid file
  -u	Unlink configuration file
```

## Example

Config:
```json
{
  "notify": {
    "threshold": 1,
    "delay": "5s"
  },
  "async": {
    "run": {
      "commands": [],
      "env": [],
      "shell_path": ""
    },
    "request": {
      "urls": []
    },
    "timeout": "16s"
  },
  "kill": {
    "uids": [],
    "signal": 9
  },
  "remove": {
    "paths": []
  },
  "run": {
    "commands": [],
    "env": [],
    "shell_path": ""
  }
}
```

To default run:
```sh
$ cleaner -c ~/cleaner.json
```
