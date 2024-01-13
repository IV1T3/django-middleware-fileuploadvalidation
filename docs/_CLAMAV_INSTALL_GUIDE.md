# Installation Guide for ClamAV

### Installing ClamAV on macOS

This package also utilizes the ClamAV anti-virus engine. For this, it is required to have a running instance of the ClamAV daemon.

```bash
brew install clamav
cd /usr/local/etc/clamav
cp freshclam.conf.sample freshclam.conf
cp clamd.conf.sample clamd.conf
```

Open `freshclam.conf` and either comment or remove the "Example" line:
```bash
# Comment or remove the line below.
# Example
```

In `clamd.conf`, uncomment the line "LocalSocket" and set it to the path of the socket file:
```bash
LocalSocket /var/run/clamav/clamd.ctl
LocalSocketGroup clamav
```

Afterwards, update the local ClamAV database.
```bash
freshclam
```

Restart the clamAV daemon.

### Installing ClamAV on Ubuntu

```bash
sudo apt-get install clamav-daemon clamav-freshclam clamav-unofficial-sigs
sudo freshclam
sudo service clamav-daemon start
```

To further configure your ClamAV daemon, modify either `/etc/clamav/clamd.conf` or `/etc/clamav/freshclam.conf`.