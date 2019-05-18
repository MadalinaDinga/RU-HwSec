# Usage
- To compile and start pos terminal use
	`make run-pos-terminal`

- To compile and start reload terminal use
	`make run-reload-terminal`

- To compile and start issuer terminal use
	`make run-issuer-terminal`

- To compile and update applet use
	`make update-applet`

- To remove all output files from building use
	`make clean`

## Makefile
Make sure the following variables are set correctly for your project:
- `APPLET_PACKAGE=applet`
- `APPLET_MAIN_CLASS=SomeApplet`
- `TERMINAL_PACKAGE=terminal`
- `TERMINAL_MAIN_CLASS_POS=SomeTerminal`
- `TERMINAL_MAIN_CLASS_RELOAD=SomeTerminal`
- `TERMINAL_MAIN_CLASS_ISSUER=SomeTerminal`

