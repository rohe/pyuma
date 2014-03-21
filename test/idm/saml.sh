#!/bin/bash

startme() {
    cd idp
    ./idp.py idp_conf &
    cd ../sp
    ./sp.py sp_conf &
    cd ..
}

stopme() {
    pkill -f "idp.py"
    pkill -f "sp.py"
}

case "$1" in
    start)   startme ;;
    stop)    stopme ;;
    restart) stopme; startme ;;
    *) echo "usage: $0 start|stop|restart" >&2
       exit 1
       ;;
esac