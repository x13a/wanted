PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
NAME := cleaner
TARGET_DIR := ./target
TARGET := $(TARGET_DIR)/$(NAME)

all: build

build:
	go build -o $(TARGET) ./src

install:
	install -d $(BINDIR)/
	install $(TARGET) $(BINDIR)/

uninstall:
	rm -f $(BINDIR)/$(NAME)

clean:
	rm -rf $(TARGET_DIR)/
