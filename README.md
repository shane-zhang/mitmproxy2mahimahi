# mitmproxy2mahimahi

This project is a tool to convert recordings done in [mitmproxy](https://github.com/mitmproxy/mitmproxy) into the [mahimahi](https://github.com/ravinet/mahimahi) protobuf format for replay.

Recordings of mitmproxy are much better as SSL/TLS support is better supported.

## Usage

mitmproxy2mahimahi depends on mitmproxy 2.x which is based on python3. All the Debian packages for mitmproxy are for ancient versions based on python2.

Which means installing mitmproxy from pip3, along with other dependencies for mitmproxy2mahimahi:

````
sudo pip3 install mitmproxy
sudo apt-get install python3-protobuf python3-tz
curl -sL https://deb.nodesource.com/setup_current.x | sudo -E bash -
sudo npm install browsertime
Then it should run with:
```

Then you can run the scripts in this repository using `mitmdump` tool.

```
mitmdump -s "mitmproxy2mahimahi-master/mitmproxy2mahimahi.py output_folder_name"
```

```
mitmdump --no-http2 --ssl-insecure -s mitmproxy2mahimahi.py
```

sudo pip3 install mitmproxy==9.0.0

```
browsertime -n 1 --chrome.args proxy-server="127.0.0.1:8080" --xvfb --screenshot https://www.epicgames.com
```
````


curl -sL https://deb.nodesource.com/setup_current.x | sudo -E bash -

sudo apt-get install -y python3-protobuf python3-tz python3 python3-pip tshark xvfb nodejs

sudo adduser $(whoami) wireshark

sudo pip3 install mitmproxy scapy

wget https://svr6.shane6.net/google-chrome-stable_current_amd64.deb --no-check-certificate

sudo apt install -y ./google-chrome-stable_current_amd64.deb

sudo npm install browsertime -g

git clone https://github.com/shane-zhang/mitmproxy2mahimahi.git
