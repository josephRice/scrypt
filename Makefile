all: libscrypt.a

UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
	LFLAGS=/usr/local/lib/libscrypt.so
endif
ifeq ($(UNAME), Darwin)
	LFLAGS=/usr/local/lib/libscrypt.dylib
endif


libscrypt.a:
	dmd -L$(LFLAGS) -lib -of=libscrypt.a source/scrypt.d

clean:
	rm -f libscrypt.a

unittest:
	dmd -unittest -main -L/usr/local/lib/libscrypt.dylib source/scrypt.d
	./scrypt
	rm scrypt{,.o}