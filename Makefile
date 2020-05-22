PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SYSCONFDIR ?= $(PREFIX)/etc
NAME := wanted
CONF_NAME := $(NAME).json
TARGET_DIR := ./target
TARGET := $(TARGET_DIR)/$(NAME)

all: build

build:
	go build -o $(TARGET) ./src/

install:
	install -d $(BINDIR)/ $(SYSCONFDIR)/
	install $(TARGET) $(BINDIR)/
	install -b -m 0600 ./config/$(CONF_NAME) $(SYSCONFDIR)/

uninstall:
	rm -f $(BINDIR)/$(NAME)
	rm -f $(SYSCONFDIR)/$(CONF_NAME)

clean:
	rm -rf $(TARGET_DIR)/
