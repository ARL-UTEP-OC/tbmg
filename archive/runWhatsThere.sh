#!/bin/bash

MODELNAME=$1

cd ns-allinone-3.23/ns-3.23/
./waf configure
make
./waf --run scratch/$MODELNAME
