build-tests: build-lib
	cd tests && make

build-lib:
	dmd -c -g dfio.d -fPIC
	dmd -c -g BlockingQueue.d
	dmd -g -oflibdfio.so dfio.o -shared -L-rpath=dfio
	cp libdfio.so tests/

test-all: build-tests
	cd tests && ./compiles_n_runs
	cd tests && ./simple_read_write

test-compiles_n_runs: build-tests
	cd tests && ./compiles_n_runs

test-simple_read_write: build-tests
	cd tests && ./simple_read_write

clean:
	cd tests && make clean
	rm -f *.o *.so main
