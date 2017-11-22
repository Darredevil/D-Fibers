build:
	dmd -c dfio.d -fPIC
	dmd -oflibdfio.so dfio.o -shared -L-rpath=/home/alexandru/workspace/dlang/D-Fibers/dfio-1.0
	dmd -c main.d
	dmd main.o -L=libdfio.so -L-rpath=.:/home/alexandru/workspace/dlang/D-Fibers/dfio-1.0

clean:
	rm -f *.o *.so main
