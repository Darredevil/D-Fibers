build: compiles_n_runs \
	simple_read_write

simple_read_write:
	dmd -g -I.. -c simple_read_write.d
	dmd -g simple_read_write.o ../BlockingQueue.o -L=../libdfio.so -L-rpath=.:../

compiles_n_runs:
	dmd -g -I.. -c compiles_n_runs.d
	dmd -g compiles_n_runs.o ../BlockingQueue.o -L=../libdfio.so -L-rpath=.:../

clean:
	rm -f *.o *.so compiles_n_runs simple_read_write

