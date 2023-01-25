import sys
import os
import time

os.system("mitmdump --no-http2 --ssl-insecure -s mitmproxy2mahimahi.py &")
time.sleep(5)
os.system("browsertime -n 1 --chrome.args proxy-server=\"127.0.0.1:8080\" --xvfb --screenshot https://%s" % sys.argv[1])
os.system("pkill mitmdump")
time.sleep(5)
os.system("mv www.example.com %s" % sys.argv[1])
print ("end")
