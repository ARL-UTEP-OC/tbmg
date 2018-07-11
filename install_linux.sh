#!/usr/bin/env bash

#environment variables have default values, but should be set before calling the installer
if [ -z "$VENV_NAME" ]; then
    echo "Warning: VENV_NAME was not set, using: creator-container" 
    VENV_NAME=tbmg-container
fi

apt-get install libnetfilter-queue-dev
apt-get install python
apt-get install python-tk
apt install python-pip
modprode ip_tables
#for AFL
#git clone https://github.com/mirrorer/afl
#cd ./afl
#make
#make install
#cd ..
#rm -r afl #?


pip install virtualenv
virtualenv $VENV_NAME

source ./$VENV_NAME/bin/activate
pip install jinja2
pip install scapy
pip install netifaces

#for AFL
#pip2 install python-afl
python -m pip install -U pip setuptools
python -m pip install ttkthemes

echo "#!/usr/bin/env bash" > start_tbmg.sh
echo "#The name of the container used during installation" >> start_tbmg.sh
echo VENV_NAME=$VENV_NAME >> start_tbmg.sh
echo >> start_tbmg.sh
echo "#Activate the container and invoke the gui" >> start_tbmg.sh
echo source ./$VENV_NAME/bin/activate >> start_tbmg.sh
echo cd bin >> start_tbmg.sh
echo modprode ip_tables
echo python2.7 TBMG2.py >> start_tbmg.sh
chmod 755 start_tbmg.sh
echo
echo
echo Type: ./start_tbmg.sh to start the TBMG