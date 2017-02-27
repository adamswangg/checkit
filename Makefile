CFLAGS=/nologo

EXE=checkit.exe
OBJS=md5.obj checkit.obj

all: $(EXE)

$(EXE): $(OBJS)
	link $(LINKFLAGS) /NOLOGO /subsystem:console /out:$(EXE) kernel32.lib $(OBJS)

clean:
	del /Q $(EXE) $(OBJS)

