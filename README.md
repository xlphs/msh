## MiniSHell

This is a toy shell written in ANSI C.

It has most of the basic featues you would expect in a shell, including:

- execute (built-in) commands and files
- shell variables
- background jobs
- piping and redirection
- exit traps

It does not do:

- tab completion
- command history
- bg/fg job management

Everything is dumped into one file to keep it simple.

To test it:

	make
	./msh < tests/test.txt

That's it.
