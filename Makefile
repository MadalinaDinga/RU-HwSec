# Definitions
JC_HOME=lib/java_card_kit-2_2_1

JC_PATH=${JC_HOME}/lib/apdutool.jar:${JC_HOME}/lib/apduio.jar:${JC_HOME}/lib/converter.jar:${JC_HOME}/lib/jcwde.jar:${JC_HOME}/lib/scriptgen.jar:${JC_HOME}/lib/offcardverifier.jar:${JC_HOME}/lib/api.jar:${JC_HOME}/lib/installer.jar:${JC_HOME}/lib/capdump.jar:${JC_HOME}/samples/classes:${CLASSPATH}

CONVERTER=java -Djc.home=${JC_HOME} -classpath ${JC_PATH}:CardApplet/bin com.sun.javacard.converter.Converter
GP=java -jar lib/gp/gp.jar

CLASS_PATH=bin/:${JC_PATH}:lib/bcprov-jdk15on-161.jar:lib/commons-lang3-3.9.jar 

# Variables for reusablity
P_AID=0x12:0x34:0x56:0x78:0x90
AID=${P_AID}:0xAB

CAP_FILES=bin/cap
APPLET_PACKAGE=applet
APPLET_MAIN_CLASS=PurseApplet
TERMINAL_PACKAGE=terminal
TERMINAL_MAIN_CLASS_POS=PoSTerminalGUI
TERMINAL_MAIN_CLASS_RELOAD=ReloadPurseTerminal
TERMINAL_MAIN_CLASS_ISSUER=PurseInitializationTerminal
COMMON_PACKAGE = common


convert-applet: compile-applet
	# Converting to cap file	
	${CONVERTER} -v -out CAP -exportpath ${JC_HOME}/api_export_files -classdir bin/ -d ${CAP_FILES} -applet ${AID} ${APPLET_PACKAGE}.${APPLET_MAIN_CLASS}  ${APPLET_PACKAGE} ${P_AID} 1.0

update-applet: convert-applet
	# Uninstall old applet
	${GP} --uninstall ${CAP_FILES}/${APPLET_PACKAGE}/javacard/applet.cap
	# Installing applet
	${GP} --install ${CAP_FILES}/${APPLET_PACKAGE}/javacard/applet.cap

compile-applet: 
	#Compiling 
	find src/${APPLET_PACKAGE}/ -name "*.java" > applet-sources.txt
	find src/${COMMON_PACKAGE}/ -name "*.java" >> applet-sources.txt
	javac -source 1.3 -target 1.1 -d bin/ -cp ${JC_PATH} @applet-sources.txt
	rm applet-sources.txt

run-issuer-terminal: terminal
	# Invoke main class
	java -classpath ${CLASS_PATH} ${TERMINAL_PACKAGE}.${TERMINAL_MAIN_CLASS_ISSUER}

run-reload-terminal: terminal
	# Invoke main class of reload terminal
	java -classpath ${CLASS_PATH} ${TERMINAL_PACKAGE}.${TERMINAL_MAIN_CLASS_RELOAD}

run-pos-terminal: terminal
	# Invoke main class POS terminal
	java -classpath ${CLASS_PATH} ${TERMINAL_PACKAGE}.${TERMINAL_MAIN_CLASS_POS}	

terminal: compile-terminal

compile-terminal: 
	# Find all source files
	find src/${TERMINAL_PACKAGE}/ -name "*.java" > terminal-sources.txt
	find src/${COMMON_PACKAGE}/ -name "*.java" >> terminal-sources.txt
	# Compile source files
	javac -classpath ${CLASS_PATH} -d bin/ @terminal-sources.txt 
	# Remove generated auxiliary file
	rm terminal-sources.txt 

clean:
	rm -rf bin/${APPLET_PACKAGE}
	rm -rf bin/cap/*
	rm -rf bin/${TERMINAL_PACKAGE}
	find bin/ -maxdepth 1 -type f -delete

uninstall:
	${GP} --delete ${P_AID}

init:
	mkdir bin bin/cap 
	mkdir src src/${APPLET_PACKAGE} src/${TERMINAL_PACKAGE} 
