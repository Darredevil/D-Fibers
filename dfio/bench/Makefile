build: hello-dlang \
	hello-golang \
	abc

abc: ab.c
	gcc -O2 ab.c -o abc -lpthread

hello-dlang: static_http/hello.d
	dmd $(DFLAGS) -I.. -c static_http/hello.d -I../../http-parser.d/out/di ../../http-parser.d/out/http-parser.a
	dmd $(DFLAGS) hello.o ../../http-parser.d/out/*.o  -L=../libdfio.so -L-rpath=.:../ -ofhello-dlang

hello-golang: static_http/hello.go
	go build -o hello-golang $<

simple-bench: abc hello-dlang
	rm -f *.csv
	(./hello-dlang &) && (./abc hello-dlang '[0-1k:100kA+10x3]' localhost:8080/) && (pkill hello-dlang)
	cp *.csv results/dmd.csv
	cd results && ./extract_plot_data.sh dmd.csv && gnuplot -c plot_bench.plt "DMD Benchmark" "dmd_bench.png" "dmd.csv.dat"

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


