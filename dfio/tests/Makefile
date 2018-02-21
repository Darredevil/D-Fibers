build: compiles_n_runs \
	ping_pong_fiber_half_duplex \
	ping_pong_thread_half_duplex \
	ping_pong_full_duplex \
	ping_pong_full_duplex_n \
	poll_timer \
	echo_server

compiles_n_runs: compiles_n_runs.d
	$(DC) $(DFLAGS) -I.. -c compiles_n_runs.d
	$(DC) $(DFLAGS) compiles_n_runs.o  -L=../libdfio.so -L-rpath=.:../

ping_pong_fiber_half_duplex: ping_pong_fiber_half_duplex.d
	$(DC) $(DFLAGS) -I.. -c ping_pong_fiber_half_duplex.d
	$(DC) $(DFLAGS) ping_pong_fiber_half_duplex.o  -L=../libdfio.so -L-rpath=.:../

ping_pong_thread_half_duplex: ping_pong_thread_half_duplex.d
	$(DC) $(DFLAGS) -I.. -c ping_pong_thread_half_duplex.d
	$(DC) $(DFLAGS) ping_pong_thread_half_duplex.o  -L=../libdfio.so -L-rpath=.:../

ping_pong_full_duplex: ping_pong_full_duplex.d
	$(DC) $(DFLAGS) -I.. -c ping_pong_full_duplex.d
	$(DC) $(DFLAGS) ping_pong_full_duplex.o  -L=../libdfio.so -L-rpath=.:../

ping_pong_full_duplex_n: ping_pong_full_duplex_n.d
	$(DC) $(DFLAGS) -I.. -c ping_pong_full_duplex_n.d
	$(DC) $(DFLAGS) ping_pong_full_duplex_n.o -L=../libdfio.so -L-rpath=.:../

poll_timer: poll_timer.d
	$(DC) $(DFLAGS) -I.. -c poll_timer
	$(DC) $(DFLAGS) poll_timer.o -L=../libdfio.so -L-rpath=.:../

echo_server: echo_server.d
	$(DC) $(DFLAGS) -I.. -c echo_server.d -I../../http-parser.d/out/di ../../http-parser.d/out/http-parser.a
	$(DC) $(DFLAGS) echo_server.o ../../http-parser.d/out/*.o  -L=../libdfio.so -L-rpath=.:../

clean:
	rm -f *.o *.so
	find . -executable -type f -delete

