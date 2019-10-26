CC:=gcc
CFLAGS:=-std=gnu99
LIBS:=-Ilib/
OBJS:= $(patsubst %.c, %.o, $(subst lib/,,$(wildcard lib/*.c)))
TEST:= $(patsubst %.c, %.out, $(subst test/,,$(wildcard test/*.c)))
EXEC:= libpcap_sent_example.out

all: $(OBJS) $(TEST) $(EXEC)

%.o: lib/%.c 
	$(CC) $(CFLAGS) -c $^ -lpcap 

%.out: test/%.c 
	$(CC) -o $@ $< -lpthread

libpcap_sent_example.out: libpcap_sent_example.c
	$(CC) $(LIBS) -o $@ $(OBJS) $< -lpcap

.PHONY=clean

clean:
	rm $(EXEC) $(OBJS)
