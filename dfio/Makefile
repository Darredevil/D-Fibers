build-tests: build-lib
	cd tests && make

build-lib:
	dmd -c -g dfio.d -fPIC
	dmd -c -g BlockingQueue.d
	dmd -g -oflibdfio.so dfio.o -shared -L-rpath=/home/alexandru/workspace/dlang/D-Fibers/dfio-1.0
	cp libdfio.so tests/

run: build-tests
	# cd tests && ./compiles_n_runs
	cd tests && ./simple_read_write

clean:
	cd tests && make clean
	rm -f *.o *.so main
