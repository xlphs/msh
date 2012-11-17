msh:
	gcc -o msh -Wall msh.c

msh.o: msh.c
	gcc -o msh.o -Wall msh.c

clean:
	rm msh.o
