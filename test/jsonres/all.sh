#!/bin/bash

startme() {
    ./as_srv.py &
    ./pbryan.py &
}

stopme() {
    pkill -f "as_srv.py"
    pkill -f "pbryan.py"
}

case "$1" in
    start)   startme ;;
    stop)    stopme ;;
    restart) stopme; startme ;;
    *) echo "usage: $0 start|stop|restart" >&2
       exit 1
       ;;
esac