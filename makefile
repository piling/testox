## Testox Make file ##
# v0.0

SRC = $(wildcard ./*.c)
OBJ = $(SRC:.c=.o)

DEPS = libtoxcore lsodium

all: test

test: $(OBJ)
	@echo " Linking $@"
	$(CC) $(CFLAGS) $(OBJ) ../toxcore/*.o -o testox

$(OBJ): %.o: %.c
	@echo " Compling $@"
	@$(CC) $(CFLAGS) -o %@ $<

clean:
	rm -f *.o
