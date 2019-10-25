CC:=gcc
EXEC:= lab1.out lab2-sleep.out lab2-rdtsc.out thread_ver.out libpcap_sent_example.out

all: $(EXEC)

lab1.out: measure_cpu_clock.c
	$(CC) -o $@ $<

lab2-sleep.out: pkt_gen.c
	$(CC) -o $@ $<

lab2-rdtsc.out: rdtsc_pkt_gen.c
	$(CC) -o $@ $<

thread_ver.out: thread_ver.c
	$(CC) -o $@ $< -lpthread

libpcap_sent_example.out: libpcap_sent_example.c
	$(CC) -o $@ $< -lpcap

.PHONY=clean

clean:
	rm $(EXEC)
