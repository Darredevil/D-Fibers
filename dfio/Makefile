build-tests: libdfio.so BlockingQueue.o
	cd tests && make

BlockingQueue.o:
	dmd -c -g BlockingQueue.d

libdfio.so: dfio.d
	dmd -c -g dfio.d -fPIC
	dmd -g -oflibdfio.so dfio.o -shared -L-rpath=dfio
	cp libdfio.so tests/

test-all: build-tests
	cd tests && ./compiles_n_runs
	cd tests && ./ping_pong_fiber_half_duplex
	cd tests && ./ping_pong_thread_half_duplex
	cd tests && ./ping_pong_full_duplex
	cd tests && ./ping_pong_full_duplex_4
	cd tests && ./ping_pong_full_duplex_8
	cd tests && ./ping_pong_full_duplex_20

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

clean:
	cd tests && make clean
	rm -f *.o *.so main
