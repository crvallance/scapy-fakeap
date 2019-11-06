#!/bin/bash
pip2 uninstall scapy-fakeap -y
cd cv_scapy-fakeap
git checkout py2-logging
cd ..
pip2 install ./cv_scapy-fakeap
##
pip3 uninstall scapy-fakeap -y
cd cv_scapy-fakeap
git checkout logging
cd ..
pip3 install ./cv_scapy-fakeap

