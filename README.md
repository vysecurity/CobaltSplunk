# CobaltSplunk Splunk Application

## Authors

- **Vincent Yiu (@vysecurity)** - Original author of CobaltSplunk
- **Mariusz B. /mgeeky (@mariuszbit)** - General App refactor introducing support for CobaltStrike 4.3+, tracking screenshots/keystrokes/teamserver_events, reworking Raport queries and polishing other things. 
- **ADARMA ( tomasz.dziwok@adamra.com )** - Based on his "VirusTotal Malware Lookup" / TA-VirusTotal Splunk App, VirusTotal integration is being added to CobaltSplunk.

## Blog Post

https://vincentyiu.com/red-team/attack-infrastructure/cobaltsplunk

## What is CobaltSplunk?

CobaltSplunk is a Splunk Application that knows how to 1) ingest Cobalt Strike related logs and parse them properly, 2) display useful operational dashboards, 3) display relevant reports.


## Usage

Manually:

0) Install Splunk
	We can grab _Splunk Enterprise Trial_ (Splunk Free) which gives us 60 days of enterprise features evaluation period.
	During that time we'll be limited to upload no more than 500MB of data per file.
	Download your `splunk-8.1.2-545206cc9f70-linux-2.6-amd64.deb` package, then hit:
	`$ sudo dpkg -i splunk-8.1.2-545206cc9f70-linux-2.6-amd64.deb`

	After getting Splunk installed, enable it to run on boot-start as well as setup Administration account's username & password:

	`$ sudo /opt/splunk/bin/splunk enable boot-start`

1) Download Cobalt.spl
2) Install as application: Apps -> Manage Apps -> Install app from file
   or using CLI: `$ /opt/splunk/bin/splunk install app <Cobalt.spl> -auth User:Password`

3) Ingest logs
	In a simplest way: 
		Add Data -> Monitor -> Files & Directories -> CobaltStrike logs directory
		-> Host: Regular expression on path -> Host field value: `\d{6}/([a-zA-Z-\._0-9]+)/\w+` -> Index: `cobalt` -> Save

4) View the dashboard and reports as you see fit

Or you can use automated script attached to this repository like so:

```
./install-splunk.sh <username> <password> <logs-path> [path-to-CobaltSplunk.spl]
```

The script will automatically create `cobalt` index if none exists, install CobaltSplunk application pointed by last argument, add `operator` role to the specified username, that has default index switched to `cobalt` (so that `Data Summary` functionality will include Cobalt Strike events by default) and add monitored Teamserver log files as specified by location supplied in third parameter of the script.

Example run:

```
$ ./install-splunk.sh admin Password1! /media/sf_vmshared/cobalt/linux/logs ./Cobalt.spl
```

## Getting Started

To build your first queries searching through Cobalt Strike logs, go to the Search view and open your query with one of the helper operators:

- `index=cobalt` - Tells Splunk to search through cobalt-related events
- `sourcetype=beacon_log` - Tells Splunk to search through specific logfiles/sourcetypes, further discussed below.
- `source="*beacon_137*.log"` - Examines specific source file with wildcards in its path.

After any of these operators are specified, you can start expanding your search queries by adding further statements, values and specific search conditions.

Example: 

_To find commands issued by specific operator:_

```
sourcetype=beacon_log type=input operator=mariusz
```

However this search query will return Events, which is not something especially readable and digestible. Therefore we can enhance that search query bit further to visualise it in form of a table perhaps:

```
sourcetype=beacon_log type=input operator=mariusz
| table _time host operator command
| sort _time
```

A bit better. How about filtering only entries that were issued on a specific host? No problem at all:

```
sourcetype=beacon_log type=input operator=mariusz host="192.168.50.14"
| table _time host operator command
| sort _time
```

## App Functionality

This Splunk app collects all events coming from Cobalt Strike data inputs in `index=cobalt` and defines several useful _sourcetypes_ based on supplied Cobalt Strike logs contents. 

Defined _sourcetypes_:

- `sourcetype=beacon_log` - Contains various log entries from `beacon_*.log` files.
- `sourcetype=weblog` - Teamserver Web Server access log entries `weblog_*.log` files.
- `sourcetype=screenshots` - List of screenshots taken by Beacons `screenshots.log` files.
- `sourcetype=teamserver_events` - Teamserver events log entries:  `events.log` files.
- `sourcetype=keystrokes` -  Keystrokes collected across Beacons `keystrokes_*.log` files.

These sourcetypes can facilitate searches by introducing pre-built regular expressions that extract interesting fields.

Each of these entries bring its own set of extracted fields, described below:

### `sourcetype=beacon_log`


Example log entries:

```
04/09 11:26:34 UTC [metadata] beacon_1830434858 -> 172.16.100.173; computer: DCORP-STD173; user: SYSTEM *; process: dllhost.exe; pid: 4364; os: Windows; version: 10.0; beacon arch: x64 (x64)
04/09 11:26:33 UTC [output]
established link to parent beacon: 172.16.100.173

04/09 11:26:34 UTC [task] <> Tasked Beacon to find svchost.exe running as SYSTEM * and make it the PPID.
04/09 11:26:34 UTC [input] <admin> blockdlls start
04/09 11:26:34 UTC [task] <T1106> Tasked beacon to block non-Microsoft binaries in child processes
04/09 11:26:36 UTC [checkin] host called home, sent: 417607 bytes
04/09 11:26:41 UTC [output]
```

Available fields:

- `date_time` - Log entry timestamp
- `metadata` - Metadata log line, emitted when a Beacon event is processed. Contains compromised system details
- `checkin` - Checkin log entries
- `task` - The line documenting what Beacon did at that time (`Tasked beacon to...`)
- `input` - Commands issued by operators to their beacons
- `output` - Outputs from issued commands as returned by Beacons
- `type` - Type of log line, among examples: input, output, task, metadata, indicator
- `tactic` - MITRE ATT&CK Tactic ID as reported by Cobalt Strike
- `ioc` - IOCs stored in Teamserver logs issued whenever Operator is uploading a file to compromised box.

### `sourcetype=weblog`

Example log entries:

```
82.221.105.6 unknown unknown [11/26 00:40:30 UTC] "GET /favicon.ico" 404 0 "" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0 - Original IP 82.221.105.6"
82.221.105.6 unknown unknown [11/26 06:44:34 UTC] "GET /favicon.ico" 404 0 "" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0 - Original IP 82.221.105.6"
```

Available fields:

- `weblog` - A single line containing values such as ip, date_time, request, status_code, user_agent


### `sourcetype=screenshots`

Example log entries:

```
12/17 09:59:20 UTC  COMMANDOVM  1   commando    screen_5aa4e767_767910548.jpg   Firefox - My Bank
12/17 09:59:20 UTC  COMMANDOVM  1   commando    screen_5dad030e_1036629838.jpg  C:\Windows\System32\cmd.exe
```

Available fields:

- `screenshot` - A single line containing values such as date_time, computer, screenshot, user, screenshot_title


### `sourcetype=teamserver_events`

Example log entries:

```
11/27 00:33:15 UTC *** mariusz quit
11/27 11:37:20 UTC *** mariusz (127.0.0.1) joined
11/27 11:47:04 UTC *** initial beacon from commando *@192.168.56.6 (COMMANDOVM)
11/27 11:52:27 UTC *** Tasked Beacon (id: 608668554, user: COMMANDOVM\commando *, 192.168.56.6@2884) to exit
```

Available fields:

- `date_time` - A log entry timestamp
- `event` - A field containing entire event message
- `initial_beacon` - An event with initial beacon check-in
- `joined` - Operator joined information (authentication success)
- `quit` - Operator quit the server
- `hosted_file` - A file was hosted on the Teamserver webserver
- `beacon_exit` - Beacon was tasked to exit
- `chat` - An operator posted a message on Teamserver chat.


### `sourcetype=keystrokes`

Example log entries:

```
12/10 14:16:49 UTC Received keystrokes from commando in desktop 1

Mozilla Firefox - My Bank
=======
start[down]
```

Available fields:

- `date_time` - A log entry timestamp
- `metadata` - Line containing context information such as application name, desktop number, username
- `keystrokes` - Extracted keystrokes data


## Fields extraction regular expressions used

Here is the list of regular expressions comprising the `props.conf` file that instrument Splunk's indexer:

```
[beacon_log]
EXTRACT-date_time = ^(?P<date_time>\d+/\d+\s+\d+:\d+:\d+)\s+\w+\s+\[
EXTRACT-metadata = ^[/A-Z0-9:\s]+\[metadata\]\s*(?P<external_ip>[^ ]+)\s+[<>-]+\s+(?P<internal_ip>[^;]+);\s*computer:\s*\b(?P<computer>[^;]+);\s*user:\s*\b(?P<user>[^;]+);\s*process:\s*\b(?P<process_name>[^;]+);\s*pid:\s*\b(?<process_id>[^;]+);\s*os:\s*\b(?<os_main>[^;]+);\s*version:\s*\b(?P<os_version>[^;]+)(?:;\s*build:\s*\b(?P<os_build>[^;]+))?;\s*beacon\s+arch:\s*(?P<beacon_arch>[^\s]+)
EXTRACT-checkin = (?=[^c]*(?:checkin|c.*checkin)).+sent:\s*(?P<size>\d+\s+bytes)
EXTRACT-task = ^(?=[^t]*(?:task|t.*task)).+(?P<command>Tasked\s+.+)$
EXTRACT-input = (?=[^i]*(?:input|i.*input))^[^<\n]*<(?P<operator>[^>]+)>\s+(?P<command>.+)
EXTRACT-output = ^[/A-Z0-9:\s]+\[output\]\s*^(?P<output>.*)
EXTRACT-type = ^[^\[\n]*\[(?P<type>\w+)
EXTRACT-tactic = ^[/A-Z0-9:\s]+\[task\]\s*<(?P<tactic>T\d+(?:,\s*(?:T\d+))*),?\s*>
EXTRACT-ioc = ^[/A-Z0-9:\s]+\[indicator\]\s*(?P<ioc_type>[^:]+):\s+(?P<ioc>[^\s]+)\s+(?P<ioc_size>\d+)\s+bytes\s+(?P<ioc_name>.*)
EXTRACT-process = (?i)^(?P<process>(?:\[System\s+Process\])|Memory Compression|System|Registry|.+\.exe)\s+(?P<process_id>\d+)\s+(?P<parent_pid>\d+)(?:\s*(?P<arch>x\d{2})\s+(?P<user>[^\s]+)?\s+(?P<session>\d+))?
EXTRACT-file = ^(?P<filetype>[a-zA-Z])\s+(?P<size>\d+)\s+\b(?P<filetime>\d{2}\/\d{2}\/\d{4}\s+\d{2}:\d{2}:\d{2})\s+(?P<name>.*)$
EXTRACT-listpath = ^(?P<path>(?:[A-Z]:\\.*)|(?:\\.*))(?:\\\*)?\s*\n^\s*[DF]\t\d+

[weblog]
EXTRACT-weblog = ^(?P<ip>[^ ]+)[^\[\n]*\[(?P<date_time>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status_code>[^ ]+)(?:[^"\n]*"){3}(?P<user_agent>[^"]+)

[screenshots]
EXTRACT-screenshot = ^(?P<date_time>\d+/\d+\s+\d+:\d+:\d+)\s+\w+\s+(?P<computer>[^\s]+)\s+\d+\s+(?P<user>[^\s]+)\s+(?P<screenshot>[^\s]+)\s+(?P<screenshot_title>.*)

[teamserver_events]
EXTRACT-date_time = ^(?P<date_time>\d+/\d+\s+\d+:\d+:\d+)\s+\w+\s+\*\*\*\s+
EXTRACT-event = ^(?:\d+/\d+\s+\d+:\d+:\d+)\s+\w+\s+\*\*\*\s+(?P<event>.*)
EXTRACT-initial_beacon = ^(?:\d+/\d+\s+\d+:\d+:\d+)\s+\w+\s+\*\*\*\s+initial\s+beacon\s+from\s+(?P<user>[^@]+)@(?P<ip>[^[\s]+)\s+\((?P<computer>[^\)]+)\)
EXTRACT-joined = ^(?:\d+/\d+\s+\d+:\d+:\d+)\s+\w+\s+\*\*\*\s+(?P<operator>[^\s]+)\s+(?:\([^\)]+\)\s*)?joined
EXTRACT-quit = ^(?:\d+/\d+\s+\d+:\d+:\d+)\s+\w+\s+\*\*\*\s+(?P<operator>[^\s]+)\s+quit
EXTRACT-hosted_file = ^(?:\d+/\d+\s+\d+:\d+:\d+)\s+\w+\s+\*\*\*\s+(?P<operator>[^\s]+)\s+hosted\s+file\s+(?P<file>.*)
EXTRACT-beacon_exit = ^(?:\d+/\d+\s+\d+:\d+:\d+)\s+\w+\s\*\*\*\s+Tasked\s+Beacon\s+(?P<beacon>.+)\s+to\s+exit\.
EXTRACT-chat = ^(?:\d+/\d+\s+\d+:\d+:\d+)\s+\w+\s<(?P<operator>[^>]+)>\s+(?P<message>.*)

[keystrokes]
EXTRACT-date_time = ^(?P<date_time>\d+/\d+\s+\d+:\d+:\d+)\s+\w+\s+Received
EXTRACT-metadata = ^(?:\d+/\d+\s+\d+:\d+:\d+)\s+\w+\s+Received\s+keystrokes\s+from\s+(?P<user>.+)\s+in\s+desktop\s+(?P<desktop_num>\d+).+^(?P<application>.+)=======
EXTRACT-keystrokes = ^(?:\d+/\d+\s+\d+:\d+:\d+)\s+\w+\s+Received\s+keystrokes\s+[^\n]+\n^(?P<keystrokes>.*)
```
