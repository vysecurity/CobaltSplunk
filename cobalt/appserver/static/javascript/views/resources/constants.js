function get_setup_content() {
    // This function returns a JSON translation of the original Setup page

    const content_mapping = {
        "generic": [
            {
                "title": "VirusTotal API Token",
                "description": 
                    "The token for VirusTotal API is required to allow the software to connect to the remote endpoint. " +
                    "It will be stored encrypted using Splunk's default password storage mechanism. A free token will work, " +
                    "however may cause significant performance degradation due to limits imposed on frequency of queries by VirusTotal.",
                "input": {
                    "id": "vt_token_id",
                    "label": "Token",
                    "is_checkbox": false,
                    "type": "password",
                    "value": "",
                    "help": 
                        "Defaults to empty. This TA will not work without this setting. To test whether this was " +
                        "configured successfully, you may use the SPL \" | virustotal \" command in an ad-doc search and " +
                        "check if it completes successfully."
                }
            },{
                "title": "VirusTotal Batching",
                "description":
                    "The \"Max.Batch Size\" argument is dependent on the VirusTotal API key. " +
                    "It tells the TA how many resources (hashes or URLs) should be batched into one REST API query. " +
                    "The higher the number, the better the performance. Note that(officially) the free key only supports 4queries / min, so for the free key the max batch size is 4." +
                    "\nThis option only affects Hash and URL requests. The VirusTotal API does not support batched queries for IPs or Domain names at this time.",
                "input": {
                    "id": "vt_maxbatchsz_id",
                    "label": "Max. Batch Size",
                    "is_checkbox": false,
                    "type": "number",
                    "value": "4",
                    "help":
                        "Defaults to 4. Recommend increasing to improve performance. " +
                        "Recommend not increasing past 100, even with large VT licenses, as this may result in large HTTP requests / responses and increased RAM usage."
                }
            },{
                "title": "VirusTotal Command Timeout",
                "description":
                    "On versions of Splunk lower than 7.1.0, the manual \"Stop\" button for the job does not terminate the " +
                    "custom command. It becomes necessary to manually kill the python process, or restart the search head. " +
                    "This setting primarily exists to safeguard against these \"never-ending\" jobs that use this command." +
                    "\nThe recommended setting for this value differs based on usecase, environment, and VT license. " +
                    "In principal it should be configured to about two times longer than the average observed running time of the command under normal conditions. " +
                    "If a timeout occurs, it will be indicated as a warning in the job interface." +
                    "\nThis setting controls the timeout for the command. If the command has been running for more than X seconds, it will terminate itself. " +
                    "This can be set to 0, to disable the timeout." +
                    "Although this timeout is not likely to be necessary often, it is a good idea to set it as a \"sanity-check\"." +
                    "In case something unexpected goes wrong with the command, this timeout will automatically terminate it after X seconds.",
                "input": {
                    "id": "vt_cmdtout_id",
                    "label": "Command Timeout",
                    "is_checkbox": false,
                    "type": "number",
                    "value": "14400",
                    "help":
                        "Defaults to 14400. This equals 4 hours."
                }
            }
        ]
    };
    
    return content_mapping;
}

// ----------------------------------
// Functions to fetch content
// ----------------------------------

function get_generic_data() {
    return get_setup_content().generic;
}


export { 
    get_generic_data,
};