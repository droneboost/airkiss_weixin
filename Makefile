ELF = airkiss
SRCS = main.c 
SRCS += capture/common.c capture/osdep.c capture/linux.c capture/radiotap/radiotap-parser.c
SRCS += utils/wifi_scan.c 
OBJS = $(patsubst %.c,%.o,$(SRCS))

LIBIW = -liw -lpthread
TIMER = -lrt

CC = gcc
CCFLAGS = -c -g -Wall -Wno-unused-but-set-variable

all: $(ELF)
$(ELF) : $(OBJS)
	$(CC) $^ -o $@ libairkiss_log.a $(LIBIW) $(TIMER) 
$(OBJS):%.o:%.c
	$(CC) $(CCFLAGS) $< -o $@

clean:
	rm -f  $(ELF) $(OBJS)

.PHONY: all clean
