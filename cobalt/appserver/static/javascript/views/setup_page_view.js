"use strict";

import * as Splunk from './splunk_helpers.js'
import * as Setup from './setup_configuration.js'
import get_template from './setup_page_template.js'

const VIRUSTOTAL_CONF = 'virustotal'

define(
    ["backbone", "jquery", "splunkjs/splunk"],
    function (Backbone, jquery, splunk_js_sdk) {
        var ExampleView = Backbone.View.extend({
            // -----------------------------------------------------------------
            // Backbon Functions, These are specific to the Backbone library
            // -----------------------------------------------------------------
            initialize: function initialize() {
                Backbone.View.prototype.initialize.apply(this, arguments);
            },

            events: {
                "click button[name='save_button']": "trigger_setup",
                "click a.accordion-toggle": "toggle_vt_opts",
            },

            render: function () {
                this.el.innerHTML = get_template();

                return this;
            },

            toggle_vt_opts: function toggle_vt_opts(evt) {
                jquery('div.accordion-heading').removeClass('active');
                jquery('div.accordion-heading').siblings().css('display', 'none');
                jquery('i.icon-accordion-toggle')
                    .removeClass('icon-triangle-down-small')
                    .addClass('icon-triangle-right-small');

                jquery(evt.currentTarget).parent().addClass('active');
                jquery(evt.currentTarget).children()
                    .removeClass('icon-triangle-right-small')
                    .addClass('icon-triangle-down-small');
                jquery(evt.currentTarget).parent().siblings().css('display', 'block');
            },

            // -----------------------------------------------------------------
            // Custom Functions, These are unrelated to the Backbone functions
            // -----------------------------------------------------------------
            // ----------------------------------
            // Main Setup Logic
            // ----------------------------------
            // This performs some sanity checking and cleanup on the inputs that
            // the user has provided before kicking off main setup process
            trigger_setup: function trigger_setup() {
                // Used to hide the error output, when a setup is retried
                this.display_error_output([]);

                var param = {
                    vt_token: null,
                    vt_batch_size: null,
                    vt_cmd_timeout: null
                }

                console.log("Triggering setup");

                // Generic configuration
                var $vt_token_input = jquery("input[name=vt_token]");
                var vt_token = $vt_token_input.val();
                param.vt_token = this.sanitize_string(vt_token);

                var $vt_batch_size_input = jquery("input[name=vt_maxbatchsz]");
                var vt_batch_size = $vt_batch_size_input.val();
                param.vt_batch_size = this.sanitize_string(vt_batch_size);

                var $vt_cmd_timeout_input = jquery("input[name=vt_cmdtout]");
                var vt_cmd_timeout = $vt_cmd_timeout_input.val();
                param.vt_cmd_timeout = this.sanitize_string(vt_cmd_timeout);

                var error_messages_to_display = this.validate_setup_options(
                    param
                );

                var did_error_messages_occur = error_messages_to_display.length > 0;
                if (did_error_messages_occur) {
                    // Displays the errors that occurred input validation
                    this.display_error_output(error_messages_to_display);
                } else {
                    this.perform_setup(
                        splunk_js_sdk,
                        param
                    )
                }
            },

            does_storage_password_exist: function does_storage_password_exist(
                storage_passwords_accessor,
                username
            ) {
                var storage_passwords = storage_passwords_accessor.list();
                var storage_passwords_found = [];

                for (var index = 0; index < storage_passwords.length; index++) {
                    var storage_password = storage_passwords[index];
                    var storage_password_stanza_name = storage_password.name;
                    if (storage_password_stanza_name === ":" + username + ":") {
                        storage_passwords_found.push(storage_password);
                    }
                }
                var does_storage_password_exist = storage_passwords_found.length > 0;

                return does_storage_password_exist;
            },

            create_storage_password_stanza: function create_storage_password_stanza(
                splunk_js_sdk_service_storage_passwords,
                realm,
                username,
                value_to_encrypt,
            ) {
                var parent_context = this;

                return splunk_js_sdk_service_storage_passwords.create(
                    {
                        name: username,
                        password: value_to_encrypt,
                        realm: realm,
                    },
                    function (error_response, response) {
                        // Do nothing
                    },
                );
            },

            create_credentials: async function create_credentials(
                splunk_js_sdk_service,
                username,
                api_key,
            ) {
                // /servicesNS/<NAMESPACE_USERNAME>/<SPLUNK_APP_NAME>/storage/passwords/<REALM>%3A<USERNAME>%3A
                var realm = null;

                var storage_passwords_accessor = splunk_js_sdk_service.storagePasswords({});
                await storage_passwords_accessor.fetch();

                var does_storage_password_exist = this.does_storage_password_exist(
                    storage_passwords_accessor,
                    username
                );

                if (does_storage_password_exist) {
                    await this.delete_storage_password(
                        storage_passwords_accessor,
                        username,
                    );
                }
                await storage_passwords_accessor.fetch();

                await this.create_storage_password_stanza(
                    storage_passwords_accessor,
                    realm,
                    username,
                    api_key,
                );
            },

            delete_storage_password: function delete_storage_password(
                storage_passwords_accessor,
                username,
            ) {
                return storage_passwords_accessor.del(":" + username + ":");
            },

            // This is where the main setup process occurs
            perform_setup: async function perform_setup(splunk_js_sdk, param) {
                var app_name = "cobalt";

                var application_name_space = {
                    owner: "nobody",
                    app: app_name,
                    sharing: "app",
                };

                try {
                    // Create the Splunk JS SDK Service object

                    const splunk_js_sdk_service = Setup.create_splunk_js_sdk_service(
                        splunk_js_sdk,
                        application_name_space,
                    );

                    console.log("Setting up conf files");

                    // virustotal.conf
                    await Splunk.update_configuration_file(
                        splunk_js_sdk_service,
                        VIRUSTOTAL_CONF,
                        "settings",
                        {
                            "batch_size": param.vt_batch_size,
                            "cmd_timeout": param.vt_cmd_timeout,
                        }
                    );

                    // Save credentials in passwords conf
                    console.log("Storing credentials for [VirusTotal]");
                    await this.create_credentials(splunk_js_sdk_service, VIRUSTOTAL_CONF, param.vt_token);


                    // Completes the setup, by access the app.conf's [install]
                    // stanza and then setting the `is_configured` to true
                    await Setup.complete_setup(splunk_js_sdk_service);

                    // Reloads the splunk app so that splunk is aware of the
                    // updates made to the file system
                    await Setup.reload_splunk_app(splunk_js_sdk_service, app_name);

                    // Redirect to the Splunk Search home page
                    Setup.redirect_to_splunk_app_homepage("search");
                } catch (error) {
                    // This could be better error catching.
                    // Usually, error output that is ONLY relevant to the user
                    // should be displayed. This will return output that the
                    // user does not understand, causing them to be confused.
                    console.error(error);
                    var error_messages_to_display = [];
                    if (
                        error !== null &&
                        typeof error === "object" &&
                        error.hasOwnProperty("responseText")
                    ) {
                        var response_object = JSON.parse(error.responseText);
                        error_messages_to_display = this.extract_error_messages(
                            response_object.messages,
                        );
                    } else {
                        // Assumed to be string
                        error_messages_to_display.push(error);
                    }

                    this.display_error_output(error_messages_to_display);
                }
            },

            // ----------------------------------
            // Input Cleaning and Checking
            // ----------------------------------
            sanitize_string: function sanitize_string(string_to_sanitize) {
                var sanitized_string = string_to_sanitize.trim();

                return sanitized_string;
            },

            sanitize_boolean: function sanitize_boolean(boolean_to_sanitize) {
                var sanitized_boolean = (boolean_to_sanitize == true ? 1 : 0);

                return sanitized_boolean;
            },

            validate_setup_options: function validate_setup_options(_setup_options) {
                var error_messages = [];

                // validate here

                return error_messages;
            },

            // ----------------------------------
            // GUI Helpers
            // ----------------------------------
            extract_error_messages: function extract_error_messages(error_messages) {
                // A helper function to extract error messages

                // Expects an array of messages
                // [
                //     {
                //         type: the_specific_error_type_found,
                //         text: the_specific_reason_for_the_error,
                //     },
                //     ...
                // ]

                var error_messages_to_display = [];
                for (var index = 0; index < error_messages.length; index++) {
                    var error_message = error_messages[index];
                    var error_message_to_display =
                        error_message.type + ": " + error_message.text;
                    error_messages_to_display.push(error_message_to_display);
                }

                return error_messages_to_display;
            },

            // ----------------------------------
            // Display Functions
            // ----------------------------------
            display_error_output: function display_error_output(error_messages) {
                // Hides the element if no messages, shows if any messages exist
                var did_error_messages_occur = error_messages.length > 0;

                var error_output_element = jquery(".setup.container .error.output");

                if (did_error_messages_occur) {
                    var new_error = document.createElement("ul")
                    for (var index = 0; index < error_messages.length; index++) {
                        var error_li = document.createElement("li")
                        error_li.innerText = error_messages[index];
                        new_error.append(error_li)
                    }

                    error_output_element.empty()
                    error_output_element.append(new_error)
                    error_output_element.stop();
                    error_output_element.fadeIn();
                } else {
                    error_output_element.stop();
                    error_output_element.fadeOut({
                        complete: function () {
                            error_output_element.html("");
                        },
                    });
                }
            },
        }); // End of ExampleView class declaration

        return ExampleView;
    }, // End of require asynchronous module definition function
); // End of require statement
