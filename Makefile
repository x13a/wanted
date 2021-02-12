NAME        := wanted

prefix      ?= /usr/local
exec_prefix ?= $(prefix)
sbindir     ?= $(exec_prefix)/sbin
srcdir      ?= ./src
sysconfdir  ?= $(prefix)/etc

confname    := $(NAME).json
targetdir   := ./target
target      := $(targetdir)/$(NAME)
sbindestdir := $(DESTDIR)$(sbindir)
confdestdir := $(DESTDIR)$(sysconfdir)

all: build

build:
	# ugly fix :(
	(cd $(srcdir); go build -o ../$(target) ".")

installdirs:
	install -d $(sbindestdir)/ $(confdestdir)/

install: installdirs
	install $(target) $(sbindestdir)/
	install -b -m 0600 ./config/$(confname) $(confdestdir)/

uninstall:
	rm -f $(sbindestdir)/$(NAME)
	rm -f $(confdestdir)/$(confname)*

clean:
	rm -rf $(targetdir)/
