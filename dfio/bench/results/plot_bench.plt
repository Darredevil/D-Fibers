#!/usr/bin/gnuplot -persist

set output ARG2
set terminal png

set title ARG1
set xlabel "Number of Clients"
set ylabel "Requests per Second"
set y2label "RSS (MB)"
set yrange [0:100000]
set ytics 10000
set y2range [0:100]
set y2tics 10
set grid
set ytics nomirror
set y2tics

plot ARG3 using 1:2 title "RPS" with line, \
	ARG3 using 1:3 title "RSS" with line axes x1y2

#pause -1
