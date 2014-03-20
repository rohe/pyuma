#!/bin/bash

startme() {
    ./as_srv.py &
    ./json_rs.py &
}

stopme() {
    pkill -f "as_srv.py"
    pkill -f "json_rs.py"
}

case "$1" in
    start)   startme ;;
    stop)    stopme ;;
    restart) stopme; startme ;;
    *) echo "usage: $0 start|stop|restart" >&2
       exit 1
       ;;
esac