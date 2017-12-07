build: compiles_n_runs \
	ping_pong_fiber_half_duplex \
	ping_pong_thread_half_duplex \
	ping_pong_full_duplex

compiles_n_runs: compiles_n_runs.d
	dmd -g -I.. -c compiles_n_runs.d
	dmd -g compiles_n_runs.o ../BlockingQueue.o -L=../libdfio.so -L-rpath=.:../

ping_pong_fiber_half_duplex: ping_pong_fiber_half_duplex.d
	dmd -g -I.. -c ping_pong_fiber_half_duplex.d
	dmd -g ping_pong_fiber_half_duplex.o ../BlockingQueue.o -L=../libdfio.so -L-rpath=.:../

ping_pong_thread_half_duplex: ping_pong_thread_half_duplex.d
	dmd -g -I.. -c ping_pong_thread_half_duplex.d
	dmd -g ping_pong_thread_half_duplex.o ../BlockingQueue.o -L=../libdfio.so -L-rpath=.:../

ping_pong_full_duplex: ping_pong_full_duplex.d
	dmd -g -I.. -c ping_pong_full_duplex.d
	dmd -g ping_pong_full_duplex.o ../BlockingQueue.o -L=../libdfio.so -L-rpath=.:../

clean:
	rm -f *.o *.so
	find . -executable -delete

