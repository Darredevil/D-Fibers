DFLAGS=-O -release -inline
export DFLAGS
DC=dmd
export DC

build-tests: libdfio.so BlockingQueue.o http-parser
	$(MAKE) -C tests

bench: libdfio.so BlockingQueue.o http-parser
	$(MAKE) -C bench

simple-bench: libdfio.so BlockingQueue.o http-parser
	$(MAKE) -C bench simple-bench

simple-bench-ldc: DC=ldmd2
simple-bench-ldc: DFLAGS=-O3 -O4 -O5 -release -link-defaultlib-shared
simple-bench-ldc: libdfio.so BlockingQueue.o http-parser
	$(MAKE) -C bench simple-bench-ldc

simple-bench-go:
	$(MAKE) -C bench simple-bench-go

simple-bench-js:
	$(MAKE) -C bench simple-bench-js

BlockingQueue.o:
	$(DC) $(DFLAGS) -c BlockingQueue.d

libdfio.so: dfio.d dfio_win.d dfio_linux.d BlockingQueue.o
	$(DC) $(DFLAGS) -c dfio.d dfio_win.d dfio_linux.d
	$(DC) $(DFLAGS) -L-rpath=dfio -shared -oflibdfio.so dfio.o dfio_linux.o dfio_win.o BlockingQueue.o
	cp libdfio.so tests/

http-parser:
	cd ../http-parser.d && git submodule update --init && make

test-all: build-tests \
	test-compiles_n_runs \
	test-ping_pong_fiber_half_duplex \
	test-ping_pong_thread_half_duplex \
	test-ping_pong_full_duplex \
	test-ping_pong_full_duplex_4 \
	test-ping_pong_full_duplex_8 \
	test-ping_pong_full_duplex_20

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
