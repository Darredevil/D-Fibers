DFLAGS=-g -O -release -inline
export DFLAGS
DC=dmd
export DC

build-tests: libdfio.so BlockingQueue.o ObjectPool.o http-parser
	$(MAKE) -C tests

bench: libdfio.so BlockingQueue.o http-parser
	$(MAKE) -C bench

simple-bench: libdfio.so http-parser
	$(MAKE) -C bench simple-bench

simple-bench-ldc: DC=ldmd2
simple-bench-ldc: DFLAGS=-O3 -O4 -O5 -release -link-defaultlib-shared
simple-bench-ldc: libdfio.so http-parser
	$(MAKE) -C bench simple-bench-ldc

simple-bench-go:
	$(MAKE) -C bench simple-bench-go

simple-bench-js:
	$(MAKE) -C bench simple-bench-js

BlockingQueue.o: BlockingQueue.d
	dmd -unittest -main -run BlockingQueue.d
	$(DC) $(DFLAGS) -c BlockingQueue.d

ObjectPool.o: ObjectPool.d
	$(DC) $(DFLAGS) -c ObjectPool.d

libdfio.so: dfio.d dfio_win.d dfio_linux.d BlockingQueue.o ObjectPool.o
	$(DC) $(DFLAGS) -c dfio.d dfio_win.d dfio_linux.d
	$(DC) $(DFLAGS) -L-rpath=dfio -shared -oflibdfio.so dfio.o dfio_linux.o dfio_win.o BlockingQueue.o ObjectPool.o
	cp libdfio.so tests/

http-parser:
	cd ../http-parser.d && git submodule update --init && make

curl: libdfio.so
	$(MAKE) -C bench curl

curl-download: libdfio.so
	$(MAKE) -C bench curl-download

read-file: libdfio.so
	$(MAKE) -C bench read-file

write-file: libdfio.so
	$(MAKE) -C bench write-file

server-dlang: libdfio.so http-parser
	$(MAKE) -C bench server-dlang

run-server-dlang: server-dlang
	cd bench && ./server-dlang

run-curl-download: curl-download
	cd bench && ./curl-download

run-read-file: read-file
	cd bench && ./read-file

run-write-file: write-file
	cd bench && ./write-file

socket: libdfio.so
	$(MAKE) -C bench socket

test-all: build-tests \
	test-compiles_n_runs \
	test-ping_pong_fiber_half_duplex \
	test-ping_pong_thread_half_duplex \
	test-ping_pong_full_duplex \
	test-ping_pong_full_duplex_4 \
	test-ping_pong_full_duplex_8 \
	test-ping_pong_full_duplex_20

test-poll_timer: build-tests
	cd tests && ./poll_timer

test-compiles_n_runs: build-tests
	cd tests && ./compiles_n_runs

test-ping_pong_fiber_half_duplex: build-tests
	cd tests && ./ping_pong_fiber_half_duplex

test-ping_pong_thread_half_duplex: build-tests
	cd tests && ./ping_pong_thread_half_duplex

test-ping_pong_full_duplex: build-tests
	cd tests && ./ping_pong_full_duplex_n --count=2

test-ping_pong_full_duplex_4: build-tests
	cd tests && ./ping_pong_full_duplex_n --count=4

test-ping_pong_full_duplex_8: build-tests
	cd tests && ./ping_pong_full_duplex_n --count=8

test-ping_pong_full_duplex_20: build-tests
	cd tests && ./ping_pong_full_duplex_n --count=20

test-echo_sever: build-tests http-parser
	cd tests && ./echo_server

clean:
	$(MAKE) -C tests clean
	$(MAKE) -C bench clean
	$(MAKE) -C ../http-parser.d clean
	rm -f *.o *.so main
