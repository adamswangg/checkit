CFLAGS=/nologo

EXE=checkit.exe
OBJS=sha1.obj md5.obj checkit.obj

all: $(EXE)

$(EXE): $(OBJS)
	link $(LINKFLAGS) /NOLOGO /subsystem:console /out:$(EXE) $(OBJS)

clean:
	del /Q $(EXE) $(OBJS)

