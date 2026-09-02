Apache2:

Copy .conf
```
cp apache2/sites-available/eyetoychat-update.online.scee.com.conf /etc/apache2/sites-available/
```
Enable config
```
sudo a2ensite eyetoychat-update.online.scee.com.conf
```

Edit ports.conf
```
sudo nano /etc/apache2/ports.conf 
```
Add:
```
Listen 10443
```