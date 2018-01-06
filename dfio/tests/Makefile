build: compiles_n_runs \
	ping_pong_fiber_half_duplex \
	ping_pong_thread_half_duplex \
	ping_pong_full_duplex \
	ping_pong_full_duplex_n \
	echo_server

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

ping_pong_full_duplex_n: ping_pong_full_duplex_n.d
	dmd -g -I.. -c ping_pong_full_duplex_n.d
	dmd -g ping_pong_full_duplex_n.o ../BlockingQueue.o -L=../libdfio.so -L-rpath=.:../

echo_server: echo_server.d
	dmd -g -I.. -c echo_server.d -I./echo_server_utils/di echo_server_utils/http-parser.a
	dmd -g echo_server.o ../BlockingQueue.o echo_server_utils/*.o  -L=../libdfio.so -L-rpath=.:../

clean:
	rm -f *.o *.so
	find . -executable -type f -delete

