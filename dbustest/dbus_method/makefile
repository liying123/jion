#dbus_signal_send:dbus_signal_send.c
#	gcc -g -lglib-2.0  -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include/ -o dbus_signal_send dbus_signal_send.c

#gcc dbus_signal_send.c `pkg-config --cflags --libs glib-2.0 gthread-2.0 dbus-1 dbus-glib-1`
CC = gcc
CC_FLAGS = $(shell pkg-config --cflags glib-2.0 gthread-2.0 dbus-1 dbus-glib-1)
CC_FLAGS += -std=c99 -g
LD_FLAGS = $(shell pkg-config --libs glib-2.0 gthread-2.0 dbus-1 dbus-glib-1)

all:call reply
call:dbus_method_call.o
	$(CC) -o $@ $+ $(LD_FLAGS)
dbus_method_call.o:dbus_method_call.c
	$(CC) $(CC_FLAGS) -c -o $@ $<

reply:dbus_method_reply.o
	$(CC) -o $@ $+ $(LD_FLAGS)
dbus_method_reply.o:dbus_method_reply.c
	$(CC) $(CC_FLAGS) -c -o $@ $<

clean:
	rm -f dbus_method_call.o dbus_method_reply.o
