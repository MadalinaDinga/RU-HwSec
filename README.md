# DEMO
- To install the applet
	`make update-applet`
- To create keys and initialize the card
	`make setup`
- To run the reload terminal
	`make run-reload-terminal`
- To run the point of sale terminal
	`make run-pos-terminal`

## Makefile
Make sure the following variables are set correctly for your project:
- `APPLET_PACKAGE=applet`
- `APPLET_MAIN_CLASS=SomeApplet`
- `TERMINAL_PACKAGE=terminal`
- `TERMINAL_MAIN_CLASS_POS=SomeTerminal`
- `TERMINAL_MAIN_CLASS_RELOAD=SomeTerminal`
- `TERMINAL_MAIN_CLASS_ISSUER=SomeTerminal`

