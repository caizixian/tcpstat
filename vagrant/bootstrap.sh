#!/usr/bin/env bash
cp /vagrant/vagrant/sources.list /etc/apt/sources.list
apt-get update
apt-get install -y mongodb python-pip python-dev build-essential
apt-get clean
pip install -r /vagrant/requirements.txt -i http://pypi.douban.com/simple