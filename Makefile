# Borrowed from https://github.com/byt3bl33d3r/OffensiveNim

vpath %.exe bin/
vpath %.dll bin/
vpath %.nim src/

#NIMFLAGS = -d=danger -d=mingw -d=strip --passc=-flto --passl=-flto --opt=size
#NIMFLAGS = -d=debug -d=mingw --embedsrc=on --hints=on
NIMFLAGS = -d=release -d=mingw -d=strip --passc=-flto --passl=-flto --opt=size

SRCS_BINS = $(notdir $(wildcard src/*.nim))
SRCS_LIBS = $(notdir $(wildcard src/*.nim))
BINS = $(patsubst %.nim,%.exe,$(SRCS_BINS))
DLLS = $(patsubst %.nim,%.dll,$(SRCS_LIBS))

.PHONY: clean

default: build

build: $(BINS)

rebuild: clean build

clean:
	rm -rf bin/*.exe bin/*.dll

%.exe : %.nim
	nim c $(NIMFLAGS) --app=console --cpu=amd64 --out=bin/$*_64.exe $<
	#nim c $(NIMFLAGS) --app=console --cpu=i386 --out=bin/$*_32.exe $<

# %.dll: %.nim
# 	nim c $(NIMFLAGS) --app=lib --nomain --cpu=amd64 --out=bin/$*_64.dll $<
# 	#nim c $(NIMFLAGS) --app=lib --nomain --cpu=i386 --out=bin/$*_32.dll $<