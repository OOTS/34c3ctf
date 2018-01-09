
primepwn: primepwn.c jumpto.o
	$(CC) -o $@ -Wall -Werror primepwn.c jumpto.o

jumpto.o: jumpto.asm
	nasm -f elf64 -o $@ $<

clean:
	rm *.o primepwn

run: primepwn
	socat tcp4-l:1337,bind=127.0.0.1,reuseaddr,fork exec:./primepwn
