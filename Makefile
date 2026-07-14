NAME = woody_woodpecker

CC = gcc

CFLAGS = -Wall -Wextra -Werror

SRCS_DIR = srcs

SRCS = $(addprefix $(SRCS_DIR)/, main.c)

OBJS_DIR = objs

OBJS = $(SRCS:$(SRCS_DIR)/%.c=$(OBJS_DIR)/%.o)

all: $(NAME)

$(OBJS_DIR)/%.o: $(SRCS_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS_DIR)/main.o -o $(NAME)

clean:
	rm -rf $(OBJS)