SRCS := \
	src/cyper.c \
	src/WELL512a.c \
	src/WELL44497a.c \
	src/WELL44497b.c \
	src/uECC.c \
	src/AES256.c \
	src/SHA3.c \
#

OBJS := $(SRCS:.c=.o)

INCS := \
	-I ./include \
	-I ./src \
#

AR   := ar rcs
CC   := gcc -c
LD   := gcc

CFLAGS := -g -O0 $(INCS) -std=c11

libcyp.a: $(OBJS)
	$(AR) $@ $^

test: libcyp.a tests/main.c
	$(LD) -g -I ./include tests/main.c -o $@ -L . -l cyp 

%.o : %.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(OBJS) test libcyp.a
