CC = gcc

CFLAGS = -Wall -Wextra -Werror

all:
	$(CC) $(CFLAGS) main.c -o out