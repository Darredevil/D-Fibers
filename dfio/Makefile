DFLAGS=-O -release -inline
export DFLAGS

build-tests: libdfio.so BlockingQueue.o
	$(MAKE) -C tests

bench: libdfio.so BlockingQueue.o
	$(MAKE) -C bench

simple-bench: libdfio.so BlockingQueue.o
	$(MAKE) -C bench simple-bench

BlockingQueue.o:
	dmd $(DFLAGS) -c BlockingQueue.d

libdfio.so: dfio.d
	dmd $(DFLAGS) -c dfio.d -fPIC
	dmd $(DFLAGS) -oflibdfio.so dfio.o -shared -L-rpath=dfio
	cp libdfio.so tests/

test-all: build-tests
	cd tests && ./compiles_n_runs
	cd tests && ./ping_pong_fiber_half_duplex
	cd tests && ./ping_pong_thread_half_duplex
	cd tests && ./ping_pong_full_duplex

test-compiles_n_runs: build-tests
	cd tests && ./compiles_n_runs

test-simple_read_write: build-tests
	cd tests && ./simple_read_write

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

test-echo_sever: build-tests
	cd tests && ./echo_server

clean:
	cd tests && make clean
	cd bench && make clean
	rm -f *.o *.so main
