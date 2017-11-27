build:
	# dmd -g -I~/workspace/dlang/D-Fibers/dfio/ -c compiles_n_runs.d
	dmd -g -I~/workspace/dlang/D-Fibers/dfio/ -c simple_read_write.d
	# dmd -g compiles_n_runs.o ../BlockingQueue.o -I~/workspace/dlang/D-Fibers/dfio/ -L=../libdfio.so -L-rpath=.:/home/alexandru/workspace/dlang/D-Fibers/dfio-1.0
	dmd -g simple_read_write.o ../BlockingQueue.o -I~/workspace/dlang/D-Fibers/dfio/ -L=../libdfio.so -L-rpath=.:/home/alexandru/workspace/dlang/D-Fibers/dfio-1.0

clean:
	rm -f *.o *.so compiles_n_runs

