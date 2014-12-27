# Tcpstat

A TCP port traffic monitor written in Python.

## Dependencies:

* MongoDB: an open-source document database.
* PyMongo: a native Python driver for MongoDB.
* python-iptables: Python bindings for iptables.

## Install dependencies:

```
sudo apt-get update
sudo apt-get install -y mongodb python-pip python-dev build-essential
sudo pip install -r /vagrant/requirements.txt
```

[How to secure my MongoDB?][3]

## Developing:

* Download Vagrant box at https://cloud-images.ubuntu.com/vagrant/trusty/current/trusty-server-cloudimg-i386-vagrant-disk1.box
* `vagrant box add ubuntu/trusty32 trusty-server-cloudimg-i386-vagrant-disk1.box`
* `vagrant up`
* `vagrant provision`

## Install

This project is under heavy development. It is subject to major, breaking changes.

Don't use it on production server or even testing server.

## Wiki

[GitHub wiki page][1]

## License

MIT

## Bugs and Issues

* Feel free to create issue at [issue tracker][2]
* And please feel free to make pull requests.

[1]:https://github.com/caizixian/tcpstat/wiki
[2]:https://github.com/caizixian/tcpstat/issues
[3]:https://docs.mongodb.org/manual/administration/security/
