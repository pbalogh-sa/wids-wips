CC = gcc
CFLAGS = 
SOURCES = main.c initialize_server.c data_parser.c data_process.c ap_list.c actor.c
OBJECTS = $(SOURCES: .c = .o)
PROGRAM = wids-wips
INCLUDES = .
PREFIX=/usr/local

all: $(PROGRAM)

$(PROGRAM): $(INCLUDES) $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS)

clean:
	rm -f $(PROGRAM) *.o

install: all
	install -m 0755 $(PROGRAM) $(PREFIX)/bin
	install -m 0644 access.conf $(PREFIX)/etc
	install -m 0644 blackhole.conf $(PREFIX)/etc

uninstall: all
	rm $(PREFIX)/etc/access.conf
	rm $(PREFIX)/etc/blackhole.conf
	rm $(PREFIX)/bin/$(PROGRAM)
