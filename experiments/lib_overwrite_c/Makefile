build:
	gcc -shared -fPIC my_lib.c -o libmy_lib.so
	gcc experiment_001.c -o experiment_001
	# dmd -oflibmy_lib.so my_lib.o -shared -L-rpath=/home/alexandru/workspace/dlang/workspace/dfibers
	# dmd -c experiment_001.d
	# dmd experiment_001.o #-Llibmy_lib.so -L-rpath=.:/home/alexandru/workspace/dlang/workspace/dfibers

run: build
	LD_PRELOAD=./libmy_lib.so ./experiment_001

clean:
	rm *.o *.so
