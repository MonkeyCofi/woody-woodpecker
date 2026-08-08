NAME = woody_woodpecker

CC = gcc

CFLAGS = -Wall -Wextra -Werror

INC = inc

SRCS_DIR = srcs

SRCS = $(addprefix $(SRCS_DIR)/, parse.c main.c)

OBJS_DIR = objs

OBJS = $(SRCS:$(SRCS_DIR)/%.c=$(OBJS_DIR)/%.o)

all: $(NAME)

$(OBJS_DIR)/%.o: $(SRCS_DIR)/%.c
	$(CC) $(CFLAGS) -I./$(INC) -c $< -o $@

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -I./$(INC) $^ -o $(NAME)

clean:
	rm -rf $(OBJS)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re