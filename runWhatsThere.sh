#!/bin/bash

MODELNAME=$1

cd ns-allinone-3.26/ns-3.26/
./waf configure
make
./waf --run scratch/$MODELNAME
