./as.py &
./rs.py &
cd idp
./idp.py idp_conf &
cd ../sp
./sp.py sp_conf &
cd ..
