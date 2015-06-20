CC=gcc
CFLAGS=-Wall -Werror
DEPS=packet_writer.h
OBJ=machsniff.o packet_writer.o
LDFLAGS=-lpcap

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

machsniff.dylib: $(OBJ)
	$(CC) $(CFLAGS) -dynamiclib -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o machsniff.dylib
