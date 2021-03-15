#!/bin/bash

SPLUNK_BIN=/opt/splunk/bin/splunk

if [ $# -lt 3 ]; then
	echo "[!] Usage: ./install-splunk.sh <username> <password> <logs-path> [path-to-CobaltSplunk.spl]"
	exit 1
fi

USERNAME="$1"
PASSWORD="$2"
LOGS_PATH="$3"
COBALT_SPLUNK="$4"

if [[ ! -d "$LOGS_PATH" ]]; then
	echo "[!] Specified logs-path directory does not exist: '$LOGS_PATH'!"
	exit 1
fi

INDEX=cobalt
APPNAME=$INDEX
HOST_REGEX='\d{6}/([a-zA-Z-\._0-9]+)/\w+'

index_info=$($SPLUNK_BIN list index $INDEX -auth "$USERNAME:$PASSWORD")

if [ $? -ne 0 ]; then 
	echo "Creating index $INDEX ..."
	$SPLUNK_BIN add index $INDEX -auth "$USERNAME:$PASSWORD"

	index_info=$($SPLUNK_BIN list index $INDEX -auth "$USERNAME:$PASSWORD")

	if [ $? -ne 0 ]; then 
		echo "[!] Could not create Splunk index $INDEX ! Error:"
		echo
		echo $index_info
		exit 1
	fi
else
	echo "Index already created."
fi

if [ -f "$COBALT_SPLUNK" ]; then
	echo "Installing CobaltSplunk app from: $COBALT_SPLUNK"
	$SPLUNK_BIN install app "$COBALT_SPLUNK" -update 1 -auth "$USERNAME:$PASSWORD"

	#echo "Installing VirusTotal Malware Lookup Splunk app..."
	#wget -O /tmp/TA-VirusTotal.tar.gz 'https://gitlab.com/adarma_public_projects/splunk/TA-VirusTotal/-/archive/SplunkBase-1.2.3/TA-VirusTotal-SplunkBase-1.2.3.tar.gz'
	#$SPLUNK_BIN install app /tmp/TA-VirusTotal.tar.gz -update 1 -auth "$USERNAME:$PASSWORD"
	#rm /tmp/TA-VirusTotal.tar.gz

	$SPLUNK_BIN restart -auth "$USERNAME:$PASSWORD"
else
	echo "Splunk apps already installed."
fi

operator=$($SPLUNK_BIN list role -auth "$USERNAME:$PASSWORD" | grep 'role:' | cut -d: -f2 | grep operator)

if [ -z "$operator" ]; then
	echo "Adding 'operator' user role with default index $INDEX..."
	$SPLUNK_BIN add role operator -imported user -default_index $INDEX -auth "$USERNAME:$PASSWORD"
	$SPLUNK_BIN edit user $USERNAME -roles admin -roles operator -auth "$USERNAME:$PASSWORD"
else
	echo "User role already created."
fi

monitored=$($SPLUNK_BIN list monitor -auth "$USERNAME:$PASSWORD" | grep "$LOGS_PATH")

if [ -z "$monitored" ]; then
	echo "Adding '$LOGS_PATH' as Cobalt Strike data inputs..."

	$SPLUNK_BIN add monitor $LOGS_PATH/.../weblog.log       -index $INDEX -sourcetype weblog            -hostregex $HOST_REGEX -auth "$USERNAME:$PASSWORD"
	$SPLUNK_BIN add monitor $LOGS_PATH/.../beacon_*.log     -index $INDEX -sourcetype beacon_log        -hostregex $HOST_REGEX -auth "$USERNAME:$PASSWORD"
	$SPLUNK_BIN add monitor $LOGS_PATH/.../keystrokes_*     -index $INDEX -sourcetype keystrokes        -hostregex $HOST_REGEX -auth "$USERNAME:$PASSWORD"
	$SPLUNK_BIN add monitor $LOGS_PATH/.../events.log       -index $INDEX -sourcetype teamserver_events -hostregex $HOST_REGEX -auth "$USERNAME:$PASSWORD"
	$SPLUNK_BIN add monitor $LOGS_PATH/.../screenshots.log  -index $INDEX -sourcetype screenshots       -hostregex $HOST_REGEX -auth "$USERNAME:$PASSWORD"

else
	echo "Path '$LOGS_PATH' is already being monitored."
fi
