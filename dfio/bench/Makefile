build: hello-dlang \
	hello-golang \
	abc

abc: ab.c
	gcc -O2 ab.c -o abc -lpthread

hello-dlang: static_http/hello.d
	dmd $(DFLAGS) -I.. -c static_http/hello.d -I../../http-parser.d/out/di ../../http-parser.d/out/http-parser.a
	dmd $(DFLAGS) hello.o ../../http-parser.d/out/*.o  -L=../libdfio.so -L-rpath=.:../ -ofhello-dlang

hello-golang: static_http/hello.go
	go build -o hello-golang $<

simple-bench: abc hello-dlang
	(./hello-dlang &) && (./abc hello-dlang '[0-1k:100kA+10x3]' localhost:8080/) && (pkill hello-dlang)

simple-bench-go: abc hello-golang
	(GOMAXPROCS=1 ./hello-golang &) && (./abc hello-golang '[0-1k:100kA+10x3]' localhost:8080/) && (pkill hello-golang)

simple-bench-js: abc static_http/hello.js
	(node static_http/hello.js &) && (./abc node '[0-1k:100kA+10x3]' localhost:8080/) && (pkill node)

clean:
	rm -f *.o *.so
	find . -executable -type f -delete


