import { 
    get_generic_data
} from './resources/constants.js'

// ----------------------------------
// Functions defining UI components
// ----------------------------------

function get_field(id, value, type) {
    var name = id.replace('_id', '');

    const template_string =
        "   <div class='control shared-controls-textareacontrol control-default' data-name='" + name + "'>" +
        "     <span class='uneditable-input uneditable-input-multiline' style='display:none'></span>" +
        "     <input type='" + type + "' id='" + id + "' name='" + name + "' value='" + value + "'>" +
        "   </div>";

    return  template_string;
}


function get_help(text, restyle=false) {

    const template_string =
        "   <div class='help-block' " + (restyle == true ? "style='margin-left:10px;'" : "") + ">" +
        "     <span>" + text + "</span>" +
        "   </div>";

    return template_string;
}

// ----------------------------------
// Functions defining main sections
// ----------------------------------

function get_generic() {
    var template_string = "<h1>Generic</h1>";
    let generic_content = get_generic_data();

    generic_content.forEach((field) => {
        template_string = template_string +
        "        <div class='field " + field.input.id.replace('_id', '') + "'>" +
        "            <div class='title'>" +
        "                <div>" +
        "                    <h3>" + field.title + "</h3>" +
        "                    <p>" + field.description.replaceAll('\n', '</p><p>') + "</p>" +
        "                </div>" +
        "            </div>" +
        "            </br>" +
        "           <div class='form-horizontal control-group shared-controls-controlgroup control-group-default'>" +
        "               <label class='control-label' for='" + field.input.id + "'>" + field.input.label + "</label>" +
        "               <div role='group' class='controls controls-join'>" +
                            get_field(field.input.id, field.input.value, field.input.type) +
        "               </div>" +
                        (field.input.help === "" ? "" : get_help(field.input.help)) +
        "            </div>" +
        "        </div>";
    });

    return template_string;
}


// ----------------------------------
// Main UI template definition
// ----------------------------------

function get_template() {

    const template_string =
        "<div class='setup container'>" +
        "    <div class='left'>" +
                get_generic() +
        "        <div class='modal-footer'>" +
        "            <button name='cancel_button' class='btn btn-default'>Cancel</button>" +
        "            <button name='save_button' class='btn btn-primary'>Save</button>" +
        "        </div>" +
        "        <br/>" +
        "        <div class='error output'></div>" +
        "    </div>" +
        "</div>";

    return template_string;
}

export default get_template;
