build: hello-dlang \
	hello-golang \
	abc

abc: ab.c
	gcc -O2 ab.c -o abc -lpthread

curl: curl.d
	$(DC) $(DFLAGS) -I.. -c curl.d
	$(DC) $(DFLAGS) curl.o  -L=../libdfio.so -L-rpath=.:../ -ofcurl

curl-download: curl.d
	$(DC) $(DFLAGS) -I.. -c curl-download.d
	$(DC) $(DFLAGS) curl-download.o  -L=../libdfio.so -L-rpath=.:../ -ofcurl-download

read-file: read-file.d
	$(DC) $(DFLAGS) -I.. -c read-file.d
	$(DC) $(DFLAGS) read-file.o  -L=../libdfio.so -L-rpath=.:../ -ofread-file

write-file: write-file.d
	$(DC) $(DFLAGS) -I.. -c write-file.d
	$(DC) $(DFLAGS) write-file.o  -L=../libdfio.so -L-rpath=.:../ -ofwrite-file

socket: socket.d
	$(DC) $(DFLAGS) -I.. -c socket.d
	$(DC) $(DFLAGS) socket.o  -L=../libdfio.so -L-rpath=.:../ -ofsocket

server-dlang: server/server.d
	$(DC) $(DFLAGS) -I.. -c server/server.d -I../../http-parser.d/out/di ../../http-parser.d/out/http-parser.a
	$(DC) $(DFLAGS) server.o ../../http-parser.d/out/*.o  -L=../libdfio.so -L-rpath=.:../ -ofserver-dlang

hello-dlang: static_http/hello.d
	$(DC) $(DFLAGS) -I.. -c static_http/hello.d -I../../http-parser.d/out/di ../../http-parser.d/out/http-parser.a
	$(DC) $(DFLAGS) hello.o ../../http-parser.d/out/*.o  -L=../libdfio.so -L-rpath=.:../ -ofhello-dlang

hello-golang: static_http/hello.go
	go build -o hello-golang $<

simple-bench: abc hello-dlang
	rm -f *.csv
	(./hello-dlang &) && (./abc hello-dlang '[0-1k:100kA+10x3]' localhost:8080/) && (pkill hello-dlang)
	cp *.csv results/dmd.csv
	cd results && ./extract_plot_data.sh dmd.csv && gnuplot -c plot_bench.plt "DMD Benchmark" "dmd_bench.png" "dmd.csv.dat"

simple-bench-ldc: abc hello-dlang
	rm -f *.csv
	(./hello-dlang &) && (./abc hello-dlang '[0-1k:100kA+10x3]' localhost:8080/) && (pkill hello-dlang)
	cp *.csv results/ldc.csv
	cd results && ./extract_plot_data.sh ldc.csv && gnuplot -c plot_bench.plt "LDC Benchmark" "ldc_bench.png" "ldc.csv.dat"

simple-bench-go: abc hello-golang
	rm -f *.csv
	(GOMAXPROCS=1 ./hello-golang &) && (./abc hello-golang '[0-1k:100kA+10x3]' localhost:8080/) && (pkill hello-golang)
	cp *.csv results/go.csv
	cd results && ./extract_plot_data.sh go.csv && gnuplot -c plot_bench.plt "Golang Benchmark" "go_bench.png" "go.csv.dat"

simple-bench-js: abc static_http/hello.js
	rm -f *.csv
	(node static_http/hello.js &) && (./abc node '[0-1k:100kA+10x3]' localhost:8080/) && (pkill node)
	cp *.csv results/nodejs.csv
	cd results && ./extract_plot_data.sh nodejs.csv && gnuplot -c plot_bench.plt "NodeJS Benchmark" "nodejs_bench.png" "nodejs.csv.dat"

clean:
	rm -f *.o *.so *.csv
	find . -maxdepth 1 -executable -type f -delete


