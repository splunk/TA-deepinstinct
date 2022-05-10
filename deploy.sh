#!/bin/bash
rm -rf output
ucc-gen --ta-version $1
sudo rm -rf /opt/splunk/etc/apps/TA-deepinstinct
sudo cp -R output/TA-deepinstinct /opt/splunk/etc/apps/
sudo /opt/splunk/bin/splunk restart
