program=test
OBJ = main.o asm.o
LIBS = -lSDL2 -lGL -lGLU
OPT=-O2 -g
CC=gcc -m32
CFLAGS=${OPT}

build: ${program}

clean:
	rm -f *.o ${program}

${program}: ${OBJ}
	${CC} ${OBJ} ${LIBS} -o ${program} ${OPT}

