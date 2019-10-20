#
# Makefile for terminal-server
#

CC = gcc

#
# Choose one of the followinf DOPTs if you need debug
#

COPT = -Wall -O2
LOPT = -pthread

all:	terminal-server.c
	$(CC) $(COPT) $(LOPT) -o terminal-server terminal-server.c

clean:
	rm -f terminal-server

