build: compiles_n_runs \
	ping_pong_fiber_half_duplex \
	ping_pong_thread_half_duplex \
	ping_pong_full_duplex \
	ping_pong_full_duplex_n \
	echo_server

compiles_n_runs: compiles_n_runs.d
	dmd $(DFLAGS) -I.. -c compiles_n_runs.d
	dmd $(DFLAGS) compiles_n_runs.o ../BlockingQueue.o -L=../libdfio.so -L-rpath=.:../

ping_pong_fiber_half_duplex: ping_pong_fiber_half_duplex.d
	dmd $(DFLAGS) -I.. -c ping_pong_fiber_half_duplex.d
	dmd $(DFLAGS) ping_pong_fiber_half_duplex.o ../BlockingQueue.o -L=../libdfio.so -L-rpath=.:../

ping_pong_thread_half_duplex: ping_pong_thread_half_duplex.d
	dmd $(DFLAGS) -I.. -c ping_pong_thread_half_duplex.d
	dmd $(DFLAGS) ping_pong_thread_half_duplex.o ../BlockingQueue.o -L=../libdfio.so -L-rpath=.:../

ping_pong_full_duplex: ping_pong_full_duplex.d
	dmd $(DFLAGS) -I.. -c ping_pong_full_duplex.d
	dmd $(DFLAGS) ping_pong_full_duplex.o ../BlockingQueue.o -L=../libdfio.so -L-rpath=.:../

ping_pong_full_duplex_n: ping_pong_full_duplex_n.d
	dmd $(DFLAGS) -I.. -c ping_pong_full_duplex_n.d
	dmd $(DFLAGS) ping_pong_full_duplex_n.o ../BlockingQueue.o -L=../libdfio.so -L-rpath=.:../

echo_server: echo_server.d
	dmd $(DFLAGS) -I.. -c echo_server.d -I../utils/di ../utils/http-parser.a
	dmd $(DFLAGS) echo_server.o ../BlockingQueue.o ../utils/*.o  -L=../libdfio.so -L-rpath=.:../

clean:
	rm -f *.o *.so
	find . -executable -type f -delete

