#!/bin/bash
if [ $# -ne 4 ] ; then
    echo "usage: ./runner.sh client-ip server-ip server-local-ip <path-to-server-executable>"
    exit 1
fi
client=$1
server=$2
server_local_ip=$3
app=$4

CPIPE=$(mktemp -u)
SPIPE=$(mktemp -u)
mkfifo $CPIPE
mkfifo $SPIPE
exec 3<>$CPIPE
exec 4<>$SPIPE
cat $CPIPE | ssh $client 2>&1  &
cat $SPIPE | ssh $server 2>&1  &

echo "$app" '&' >&4
cat >&4 <<EOL
PID=$(jobs -p)
EOL

for n in `seq 100 100 100` ; do
   #echo 'perf stat -p $PID &' > &4
   echo "wrk -c $n -t 4 -d 10 http://$server_local_ip/" > &3
   sleep 10
   #echo 'kill -INT $!' > &4
done


echo "exit" >&3
echo "exit" >&4
unlink $CPIPE
unlink $SPIPE
