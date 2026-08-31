## Install

On ubuntu 22.04:
```
sudo apt-get update 
sudo apt-get install bind9
sudo apt-get install dnsutils
```

## Configuration

First modify the main configuration file for bind9.
```
sudo nano /etc/bind/named.conf.local
```
And add:
```
zone "online.scee.com" {
    type master;
    file "/etc/bind/db.online.scee.com.conf";
};
```

```
sudo cp deploy/dns/db.online.scee.com.conf /etc/bind/
```

## Restart

```
sudo systemctl restart bind9
```

