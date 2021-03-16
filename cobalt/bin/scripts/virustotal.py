#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals
import time
import sys
import os
import re
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.client import StoragePassword, Service
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

# Configurable values
API_KEY = None
PROXY = None
BATCHING = 4
CMD_TIMEOUT = -1

REPORT_TYPES = ["hash", "ip", "url", "domain"]

# Final (readonly) definitions:
ALL_OUTPUT_FIELDS = {"hash": ["vt_resource", "vt_query_time", "vt_classification", "vt_scan_date", "vt_permalink",
                              "vt_positives", "vt_total", "vt_threat_av", "vt_threat_id", "vt_hashes"],
                     "ip": ["vt_resource", "vt_whois", "vt_asn", "vt_network",
                            "vt_country", "vt_as_owner", "vt_query_time"],
                     "url": ["vt_resource", "vt_query_time", "vt_classification", "vt_scan_date", "vt_permalink",
                             "vt_positives", "vt_total", "vt_threat_av", "vt_threat_id", "vt_urls"],
                     "domain": ["vt_resource", "vt_categories", "vt_whois", "vt_classification",
                                "vt_detected_communicating_samples", "vt_detected_downloaded_samples",
                                "vt_detected_referrer_samples", "vt_detected_urls"]}


class VTRequestLimitExceededException(Exception):
    pass


class SplunkJobTerminatedException(Exception):
    def __init__(self, state):
        self.state = state


class CustomCommandTimeoutException(Exception):
    def __init__(self, runtime):
        self.runtime = runtime


class TerminationHelper:
    """
    This class is used to help detect Splunk job termination, and subsequently terminate this command.
    Due to the nature of this command, it can execute for a very long time. Splunk has difficulty terminating
    it prematurely. As such, this class was written to assist the  user with terminating this command.
    Before this was implemented, attempting to terminate a job running this command would force the job into a
    "FAILED" state while continuing to execute this command and the job.
    """

    def __init__(self, service, ctx, recheck_interval=30):
        self.last_check = time.time()
        self.service = service  # type: Service
        self.sid = ctx.metadata.searchinfo.sid
        self.splunk_ver = [int(x) for x in ctx.metadata.searchinfo.splunk_version.split('.')]
        self.recheck_interval = recheck_interval
        self.ctx = ctx
        self.start_time = time.time()
        # Versions of Splunk lower than 7.1.0 treat the job lifecycle differently
        # For those versions, this check will fail prematurely
        # As such, we only run  check_termination when splunk_version >= 7.1.0
        if self.splunk_ver[0] < 7 or (self.splunk_ver[0] == 7 and self.splunk_ver[1] < 1):
            if CMD_TIMEOUT < 1:
                ctx.write_warning("CobaltSplunk : Splunk version '%s'. "
                                  "Unable to detect user-initiated termination of custom command. "
                                  "This feature works in Splunk version 7.1.0 and later. "
                                  "It is recommended, in this case, that CMD_TIMEOUT be set to a value greater than 0."
                                  % ctx.metadata.searchinfo.splunk_version)
            self.enabled = False
        else:
            self.enabled = True

    def _check_termination(self):
        """
        Queries Splunk's service REST to get status of the job.
        If the job has been terminated, raises a SplunkJobTerminatedException
        """
        self.last_check = time.time()
        job = self.service.job(self.sid)
        state = job['dispatchState'].upper()
        if state == "FAILED" or state == "FINALIZING" or state == "FINALIZED":
            raise SplunkJobTerminatedException(state)

    def check_termination(self, now=False):
        """
        Check if the job was terminated.
        This method has a built-in timer to avoid querying the info too often.
        :param now: use True to force a re-check now, ignoring the timer.
        """

        if CMD_TIMEOUT > 0:
            runtime = time.time() - self.start_time
            if runtime > CMD_TIMEOUT:
                raise CustomCommandTimeoutException(runtime)

        if not self.enabled:
            return

        if now or (time.time() - self.last_check) > self.recheck_interval:
            self._check_termination()


def _query_virustotal_hashes(hashes, mode):
    # Keep track of how many hashes we are dealing with
    if isinstance(hashes, list):
        hash_len = len(hashes)
        query = ",".join(hashes)
    elif isinstance(hashes, str):
        hash_len = hashes.count(',')
        query = hashes
    else:
        raise Exception("Unrecognized object type passed to _query_virustotal_hashes")

    raw_results = _query_virustotal('file', {'resource': query}, hash_len)

    # Parse response into dict
    out = {}

    if mode == "json":
        for part in raw_results:
            o = out[part['resource']] = {}
            o['vt_resource'] = part['resource'].lower()
            o['vt_json_response'] = json.dumps(part)
        return out

    q_time = time.time()

    try:
        for part in raw_results:
            o = out[part['resource']] = {}
            if 'sha1' in part.keys() and 'sha256' in part.keys() and 'md5' in part.keys():
                o['hashes'] = [
                    part['md5'].lower(),
                    part['sha1'].lower(),
                    part['sha256'].lower()
                ]
            else:
                o['hashes'] = [part['resource'].lower()]
            o['resource'] = part['resource'].lower()
            o['query_time'] = q_time
            if part['response_code'] != 1:
                o['classification'] = "unknown_hash"
            else:
                o['scan_date'] = part['scan_date']
                o['permalink'] = part.get('permalink')
                o['positives'] = part['positives']
                o['total'] = part['total']
                avs = [(k, v['result']) for k, v in part['scans'].items() if v['detected'] is True]
                o['threat_av'] = [av[0] for av in avs]
                o['threat_id'] = [av[1] for av in avs]
                try:
                    o['classification'] = o['positives'] / o['total'] * 100
                except:
                    o['classification'] = 'unclassified : data missing from VT reply'
    except KeyError as ke:
        raise Exception("KeyError while parsing VT response. Key '%s' was expected but missing from the response. "
                        "Query was: %s" % (ke.message, hash))

    return out


def _query_virustotal_ips(ips, mode="v1"):
    # Keep track of how many hashes we are dealing with
    if not isinstance(ips, list):
        raise Exception("Unrecognized object type passed to _query_virustotal_ips")

    out = {}

    if mode == "json":
        for ip in ips:
            part = _query_virustotal('ip-address', {"ip": ip}, 1)[0]
            o = out[ip] = {}
            o['vt_resource'] = ip.lower()
            o['vt_json_response'] = json.dumps(part)
        return out

    # the VT API does not allow for batch querying IP addresses
    # let's do this manually
    for ip in ips:
        o = out[ip] = {}
        raw_result = _query_virustotal('ip-address', {"ip": ip}, 1)[0]
        # IPv4 is not case sensitive (obviously), but if IPv6 support is implemented, it will matter
        o['resource'] = ip.lower()
        if raw_result.get('response_code') != 1:
            o['classification'] = 'unknown_ip'
            if raw_result.get('verbose_msg') is not None:
                o['verbose_msg'] = raw_result.get('verbose_msg')
        else:
            o['classification'] = 'unclassified'
        for k,v in raw_result.items():
            if k.startswith("detected_"):
                o[k] = len(v)
        o['whois'] = raw_result.get('whois')
        o['asn'] = raw_result.get('asn')
        o['network'] = raw_result.get('network')
        o['country'] = raw_result.get('country')
        o['as_owner'] = raw_result.get('as_owner')
        o['query_time'] = time.time()

    return out


def _query_virustotal_urls(urls, mode):
    # Keep track of how many hashes we are dealing with
    if isinstance(urls, list):
        hash_len = len(urls)
        query = "\n".join(urls)
    elif isinstance(urls, str):
        hash_len = urls.count(',')
        query = urls
    else:
        raise Exception("Unrecognized object type passed to _query_virustotal_hashes")

    raw_results = _query_virustotal('url', {'resource': query}, hash_len)

    # Parse response into dict
    out = {}

    if mode == "json":
        for part in raw_results:
            o = out[part['resource']] = {}
            o['vt_resource'] = part['resource'].lower()
            o['vt_json_response'] = json.dumps(part)
        return out

    q_time = time.time()

    try:
        for part in raw_results:
            o = out[part['resource']] = {}
            if 'resource' in part.keys() and 'url' in part.keys():
                o['urls'] = list(set([part['resource'], part['url']]))
            else:
                o['urls'] = [part['resource'].lower()]

            o['resource'] = part['resource']  # This could be x.lower(), but the truth is: URLs are case sensitive
            o['query_time'] = q_time
            if part['response_code'] != 1:
                o['classification'] = "unknown_url"
            else:
                o['scan_date'] = part['scan_date']
                o['permalink'] = part.get('permalink')
                o['positives'] = part['positives']
                o['total'] = part['total']
                avs = [(k, v['result']) for k, v in part['scans'].items() if v['detected'] is True]
                o['threat_av'] = [av[0] for av in avs]
                o['threat_id'] = [av[1] for av in avs]
                try:
                    o['classification'] = o['positives'] / o['total'] * 100
                except:
                    o['classification'] = 'unclassified : data missing from VT reply'
    except KeyError as ke:
        raise Exception("KeyError while parsing VT response. Key '%s' was expected but missing from the response. "
                        "Query was: %s" % (ke.message, hash))

    return out
    pass


def _query_virustotal_domains(domains, mode):
    # Keep track of how many hashes we are dealing with
    if not isinstance(domains, list):
        raise Exception("Unrecognized object type passed to _query_virustotal_ips")

    out = {}

    if mode == "json":
        for domain in domains:
            part = _query_virustotal('domain', {"domain": domain}, 1)[0]
            o = out[domain] = {}
            o['vt_resource'] = domain.lower()
            o['vt_json_response'] = json.dumps(part)
        return out

    # the VT API does not allow for batch querying domains.
    # let's do this manually
    for domain in domains:
        o = out[domain] = {}
        raw_result = _query_virustotal('domain', {"domain": domain}, 1)[0]

        # domain names are not case sensitive as per RFC1035 (2.3.1)
        o['resource'] = domain.lower()
        if raw_result.get('response_code') != 1:
            o['classification'] = 'unknown_domain'
            if raw_result.get('verbose_msg') is not None:
                o['verbose_msg'] = raw_result.get('verbose_msg')
        else:
            o['classification'] = 'unclassified'
        o['categories'] = []
        if 'categories' in raw_result.keys():
            o['categories'] = raw_result.get('categories')

        for x in ["detected_communicating_samples", "detected_downloaded_samples",
                                "detected_referrer_samples", "detected_urls"]:
            if x in raw_result.keys():
                o[x] = len(raw_result.get(x))
            else:
                o[x] = 0

        # Iterate over all results looking for categories.
        # Store categories in array.
        for k,v in raw_result.items():
            if k.endswith(' category'):
                o['categories'].append(v)
            # This provides interesting information but cannot be relied on to be in every response.
            # The format is also not predictable.
            # As such it causes downstream issues with Splunk and the KVStore.
            # Commented out & disabled until a solution is found.
            # if k.endswith(" domain info") and isinstance(v, dict):
            #     name = k[:-12]
            #     for vk, vv in v.items():
            #         o[name+":"+vk] = vv

        o['categories'] = list(set(o['categories']))
        o['whois'] = raw_result.get('whois')
        o['query_time'] = time.time()


    return out


def _query_virustotal(endpoint_type, params, expect_n_results):
    """
    Execute HTTPs queries against VT api to get reports about HASH
    :param hash: a string or list of strings. The strings should be hex representations of MD5 or SHA256 hashes
    :return: Information from VT concerning the hashes.
    """
    import requests

    # Prepare VT request
    params['apikey'] = API_KEY
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"
    }

    response = requests.get('https://www.virustotal.com/vtapi/v2/%s/report' % endpoint_type,
                            params=params, headers=headers, proxies=PROXY)

    # Exceeded API key call rate
    if response.status_code == 204:
        raise VTRequestLimitExceededException()
    # Invalid token used
    elif response.status_code == 403:
        raise Exception("Got status code 403 from VirusTotal API. "
                        "This may indicate that an invalid token is being used. "
                        "You may change the token in app setup. ")
    # Some unexpected error occurred
    elif response.status_code != 200:
        raise Exception("Got status code %d from VirusTotal API." % response.status_code)

    json_response = response.json()
    # If queried for multiple hashes, VT returns array of results.
    # If queried for one, returns an object.
    # Therefore normalise:
    if expect_n_results == 1 and not isinstance(json_response, list):
        json_response = [json_response]

    if expect_n_results != len(json_response):
        raise Exception("Got unexpected number of results from VT API. expected: %d . got: %d" % (expect_n_results, len(json_response)))

    return json_response


def batch(gen, n=1):
    """
    Get several items from a generator
    :param gen: The generator
    :param n: The number of items to get
    :return: A list of items retrieved from the generator
    """
    records = []
    for record in gen:
        records.append(record)
        n = n - 1
        if n <= 0:
            break
    return records


@Configuration(local=True)
class VirusTotalCommand(StreamingCommand):
    hash = Option(
        doc='''
        **Syntax:** **hash=***<fieldname>*
        **Description:** Name of the field which contains the hash''',
        require=False, validate=validators.Fieldname())

    ip = Option(
        doc='''
        **Syntax:** **ip=***<fieldname>*
        **Description:** Name of the field which contains the ip''',
        require=False, validate=validators.Fieldname())

    url = Option(
        doc='''
        **Syntax:** **url=***<fieldname>*
        **Description:** Name of the field which contains the url''',
        require=False, validate=validators.Fieldname())

    domain = Option(
        doc='''
            **Syntax:** **domain=***<fieldname>*
            **Description:** Name of the field which contains the domain''',
        require=False, validate=validators.Fieldname())

    mode = Option(
        doc='''
        **Syntax:** **mode=***<raw|v1>*
        **Description:** Name of the field which contains the url''',
        require=False, default="v1", validate=validators.Set('json', 'v1'))

    rescan = Option(
        doc='''
            **Syntax:** **rescan=***<fieldname>*
            **Description:** bool. If false, will not rescan rows that already have vt_* fields.
            If true, will scan all hashes. Uses vt_resource field to determine if info exists. (Deafults True)''',
        require=False, default=True, validate=validators.Boolean())

    def correlate_vt(self, records):
        """
        Incorporate VT information into the events provided in 'records'
        :param records: The records to be supplemented with added information
        :return: None
        """
        for record in records:
            for k in ALL_OUTPUT_FIELDS[self.report_type]:
                if k not in record.keys():
                    record[k] = ""

        expected_min_resource_len = 0
        if self.report_type == "hash":
            expected_min_resource_len = 20
        elif self.report_type == "ip":
            expected_min_resource_len = 7
        elif self.report_type == "url":
            expected_min_resource_len = 4
        elif self.report_type == "domain":
            expected_min_resource_len = 4

        # Ignore records that already have info if we are not rescanning
        if not self.rescan:
            records = [record for record in records
                       if "vt_resource" not in record.keys()
                       or not isinstance(record['vt_resource'], str)
                       or len(record['vt_resource']) < expected_min_resource_len]

        already_warned = False
        # Put records into temporary dict, as cross-reference
        records_dict = {}
        resources = []
        for record in records:
            # The following checks makes sure the field is a string
            if self.matching_field in record.keys() \
                    and isinstance(record[self.matching_field], str) and len(record[self.matching_field]) >= expected_min_resource_len \
                    and record[self.matching_field] == record[self.matching_field].strip():
                _resource = record[self.matching_field]
                records_dict[_resource] = record
                resources.append(_resource)
            elif not already_warned:
                self.write_warning("VirusTotal Command: Warning: \
                One or more events had bad data or no data in your input field. \
                Normalize the field in your data to correct this issue. Note: this \
                is often caused by empty values, mvfield values, or values with leading or trailing whitespaces. \
                Warning: Unaddressed data quality issues can additionally cause subsequent failures with lookups. "
                                   )
                already_warned = True

        # If there are no hashes to scan, exit.
        if len(resources) == 0:
            self.logger.debug("Not querying VT API with %d resources" % len(resources))
            return
        self.logger.debug("Querying VT API with %d resources (%s)" % (len(resources), self.report_type))

        attempts = 0
        # Query the API
        while True:
            try:
                attempts += 1
                if self.report_type == "hash":
                    vt_res = _query_virustotal_hashes(resources, mode=self.mode)
                elif self.report_type == "ip":
                    vt_res = _query_virustotal_ips(resources, mode=self.mode)
                elif self.report_type == "url":
                    vt_res = _query_virustotal_urls(resources, mode=self.mode)
                elif self.report_type == "domain":
                    vt_res = _query_virustotal_domains(resources, mode=self.mode)
                break
            except VTRequestLimitExceededException:
                # Always log to the search.log file
                self.logger.warning("VirusTotal Request Limit Exceeded. Waiting 1 minute before resuming queries.")

                # End sleep in 60 seconds
                sleep_end_time = time.time() + 60
                while time.time() < sleep_end_time:
                    # Check if user terminated the job
                    self.termination_helper.check_termination(now=True)
                    # Sleep at most 5 seconds, and at least enough seconds to reach end of timeout period
                    time.sleep(max(0.0, min(5.0, sleep_end_time - time.time())))
            except Exception as e:
                self.error_exit(e, "Unexpected error when querying VirusTotal API: %s" % e.message)
            if attempts > 10:
                self.error_exit(None, "Failed to retrieve results from VirusTotal after 10 retries. Aborting.")

        # Verify that we got expected number of results
        if len(vt_res) != len(records_dict):
            self.error_exit(None, "VirusTotal returned %d results, but %d were expected. "
                                  "Is the batch_size value set too high for this specific key (app setup)?"
                            % (len(vt_res), len(records_dict)))

        # Place values from results into the rows we are processing.
        for k, v in vt_res.items():
            # Fill with real values from response (at least as many as we have)
            for vtk, vtv in v.items():
                if self.mode == 'v1':
                    records_dict[k]["vt_%s" % vtk] = vtv
                elif self.mode == 'json':
                    records_dict[k][vtk] = vtv

    def prepare(self):
        """
        Called by splunkd before the command executes.
        Used to get configuration data for this command from splunk.
        :return: None
        """
        global API_KEY, BATCHING, CMD_TIMEOUT, PROXY

        self.logger.debug('VirusTotalCommand: %s', self)  # logs command line

        proxy_password = None

        # Get the API key from Splunkd's REST API
        # Also get proxy password if configured
        for passwd in self.service.storage_passwords:  # type: StoragePassword
            if (passwd.realm is None or passwd.realm.strip() == "") and passwd.username == "virustotal":
                API_KEY = passwd.clear_password
            if (passwd.realm is None or passwd.realm.strip() == "") and passwd.username == "vt_proxy":
                proxy_password = passwd.clear_password

        # Verify we got the key
        if API_KEY is None or API_KEY == "defaults_empty":
            self.error_exit(None, "No API key found for VirusTotal. Re-run the app setup for the TA.")

        # Helper method to get config settings from virustotal.conf with error checking
        def get_safely(stanza, key, thetype):
            try:
                return thetype(self.service.confs[str('virustotal')][str(stanza)][str(key)])
            except:
                self.error_exit(sys.exc_info(), "VirusTotal command: Error while processing %s. "
                                                "Ensure that the batch_size variable is correctly configured (app setup)"
                                                " and that defaults.conf was not damaged. "
                                                "Error: %s" % (key, sys.exc_info()[1]))

        # Configure some common settings

        BATCHING = get_safely('settings', 'batch_size', int)
        CMD_TIMEOUT = get_safely('settings', 'cmd_timeout', int)

        # Configure proxy settings (if the user enabled the proxy in setup)

        # Following "best practice" of using "disabled" instead of "enabled" leads to bad-looking logic...
        if not get_safely('proxy', 'disabled', validators.Boolean()):
            match = re.match('^(https?|socks5)://([^@:#\$ _]+)(:(\d+))?$', get_safely('proxy', 'url', str))

            import requests
            self.logger.warning(requests.__version__)

            # We need either 2 or 4 groups, depending on whether the user specified the port
            # This regex is here mainly to sanitise/validate user input, instead of trusting that the user set it correctly
            if match is None or (len(match.groups()) != 2 and len(match.groups()) != 4):
                self.error_exit(None, "VirusTotal Command: Proxy settings appear to be incorrect. "
                                      "Go to the App Setup page and ensure that the URL for the proxy is configured correctly,")
                return

            username = get_safely('proxy', 'username', str)

            if username is not None and len(username) > 0:
                url = '%s://%s:%s@%s' % (match.group(1), username, proxy_password, match.group(2))
            else:
                url = '%s://%s' % (match.group(1), match.group(2))

            if len(match.groups()) == 4 and match.group(4) is not None:
                url = url + ":%s" % match.group(4)

            PROXY = {
                'https': url
            }

    def stream(self, records):
        """
        Hooking point for splunk.
        :param records: The generator function provided by Splunk which will provide all the events.
        :return: yields events one at a time
        """
        self.termination_helper = TerminationHelper(self.service, self)

        self.logger.debug("VirusTotalCommand: BATCHING = %d" % BATCHING)
        self.logger.debug("VirusTotalCommand: RESCAN = %s" % self.rescan)

        self.matching_field = None
        self.report_type = None
        for rt in REPORT_TYPES:
            if getattr(self, rt) is not None:
                if self.report_type is not None:
                    self.error_exit(None, "VirusTotal Command: Getting multiple types of reports in a single search is not supported. "
                                          "Specify only one of 'hash=', 'ip=', 'url=', or 'domain=' and try again.")
                    return
                self.report_type = rt
                self.matching_field = getattr(self, rt)
        if self.report_type is None:
            self.error_exit(None, "VirusTotal Command: No field specified for matching. "
                                  "Specify one of 'hash=', 'ip=', 'url=', or 'domain=' and try again.")
            return

        # Process the events
        try:
            while True:
                _records = batch(records, n=BATCHING)
                if len(_records) == 0:
                    break
                self.termination_helper.check_termination()
                self.correlate_vt(_records)
                for record in _records:
                    yield record
        except SplunkJobTerminatedException as sjt:
            warning = "VirusTotal Command: Forcing exit. Reason: Parent job termination detected. " \
                      "Parent job state: %s" % sjt.state
            self.write_warning(warning)
            self.logger.warning(warning)
            return
        except CustomCommandTimeoutException as cct:
            warning = "VirusTotal Command: Forcing exit. Reason: Internal timeout reached. " \
                      "If necessary, the timeout can be increased on the app setup page. " \
                      "Command has been running for: %d seconds" % cct.runtime
            self.write_warning(warning)
            self.logger.warning(warning)
            return


dispatch(VirusTotalCommand, sys.argv, sys.stdin, sys.stdout, __name__)
