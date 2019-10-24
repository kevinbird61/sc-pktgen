CC:=gcc
EXEC:= lab1 lab2-sleep lab2-rdtsc thread_ver

all: $(EXEC)

lab1: measure_cpu_clock.c
	$(CC) -o $@ $<

lab2-sleep: pkt_gen.c
	$(CC) -o $@ $<

lab2-rdtsc: rdtsc_pkt_gen.c
	$(CC) -o $@ $<

thread_ver: thread_ver.c
	$(CC) -o $@ $< -lpthread

.PHONY=clean

clean:
	rm $(EXEC)
