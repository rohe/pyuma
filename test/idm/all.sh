#!/bin/bash

startme() {
    ./as_srv.py &
    ./rs_srv.py &
    cd idp
    ./idp.py idp_conf &
    cd ../sp
    ./sp.py sp_conf &
    cd ..
}

stopme() {
    pkill -f "as_srv.py"
    pkill -f "rs_srv.py"
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