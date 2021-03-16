cd /root/
dpkg -i splunkforwarder*.deb
/opt/splunkforwarder/bin/splunk enable boot-start
/opt/splunkforwarder/bin/splunk add forward-server 127.0.0.1:9997
/opt/splunkforwarder/bin/splunk start
/opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log -index ssh -sourcetype %APP%
/opt/splunkforwarder/bin/splunk add monitor /root/cobaltstrike/.../weblog.log       -index cobalt -sourcetype weblog      
/opt/splunkforwarder/bin/splunk add monitor /root/cobaltstrike/.../beacon_*.log     -index cobalt -sourcetype beacon_log  
/opt/splunkforwarder/bin/splunk add monitor /root/cobaltstrike/.../keystrokes_*     -index cobalt -sourcetype keystrokes       
/opt/splunkforwarder/bin/splunk add monitor /root/cobaltstrike/.../events.log       -index cobalt -sourcetype teamserver_events
/opt/splunkforwarder/bin/splunk add monitor /root/cobaltstrike/.../screenshots.log  -index cobalt -sourcetype screenshots 
