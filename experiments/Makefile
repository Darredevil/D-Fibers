build:
	dmd -v -c my_lib.d -fPIC
	dmd -v -oflibmy_lib.so my_lib.o -shared -L-rpath=/home/alexandru/workspace/dlang/workspace/dfibers
	dmd -v -c experiment_001.d
	dmd -v experiment_001.o -L=libmy_lib.so -L-rpath=.:/home/alexandru/workspace/dlang/workspace/dfibers


clean:
	rm *.o *.so
