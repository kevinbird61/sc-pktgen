CC:=gcc
CFLAGS:=-std=gnu99 -O2
LIBS:=-lpcap -lpthread
INC:=-Ilib/
OBJS:= $(patsubst %.c, %.o, $(subst lib/,,$(wildcard lib/*.c)))
TEST:= $(patsubst %.c, %.out, $(subst test/,,$(wildcard test/*.c)))
EXEC:= $(patsubst %.c, %.exe, $(subst src/,,$(wildcard src/*.c)))

all: $(OBJS) $(TEST) $(EXEC)

%.o: lib/%.c 
	$(CC) $(CFLAGS) -c $^ $(LIBS) 

%.out: test/%.c 
	$(CC) $(INC) -o $@ $(OBJS) $< $(LIBS)

%.exe: src/%.c
	$(CC) $(INC) -o $@ $(OBJS) $< $(LIBS)

.PHONY=clean

clean:
	rm $(EXEC) $(OBJS) $(TEST)
