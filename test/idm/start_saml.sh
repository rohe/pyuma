#!/bin/bash
cd ././../idp
./idp.py idp_conf &
cd ../sp
./sp.py sp_conf &
cd ../idm
