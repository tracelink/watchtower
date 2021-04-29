$(document).ready(function() {
	// Configure tooltip
	$('[data-toggle="tooltip"]').tooltip();

	// Configure CodeMirror blocks
    var sourceCodeEditor = CodeMirror.fromTextArea(document.getElementById('sourceCode'), {
        lineNumbers: true,
        mode: "javascript"
    });
	sourceCodeEditor.setSize(null, 240);

	var astReader = CodeMirror.fromTextArea(document.getElementById('ast'), {
		lineNumbers: true,
		mode: "json",
		readOnly: true
	});
	astReader.setSize(null, 240);

    var createFunctionEditor = CodeMirror.fromTextArea(document.getElementById('createFunction'), {
    	lineNumbers: true,
    	mode: "javascript"
    });
    createFunctionEditor.setSize(null, 240);

    var createFunctionReader = CodeMirror.fromTextArea(document.getElementById('customCreateFunction'), {
        lineNumbers: true,
        mode: "javascript",
        readOnly:true
    });
    createFunctionReader.setSize(null, 240);

	// Configure custom and core rule switcher
    configureRuleTabs();

    // Configure button to add message
    $(".add-message").on("click", addMessage);

    // Configure buttons to delete messages
    $(".delete-message").on("click", deleteMessage);

	// Configure save rule modals
	configureCustomRuleModal(createFunctionReader);
	configureCoreRuleModal();
});

function configureRuleTabs() {
	// Only show active tab content on first load
	$(".rule-tab").hide();
	let active = $("#rule-tabs").children().filter('.active').attr('id');
    $("." + active).show();

	// Switch between tabs
    $("#rule-tabs").children().on('click', function(e) {
    	// Show correct tab content and highlight tab button
    	var id = e.target.id;
    	$(".rule-tab").hide();
    	$("#rule-tabs").children().removeClass('active');
        $("." + id).show();
        $("#" + id).addClass('active');
		// Update form value of "core" for running rule
        if (id.includes("core")) {
        	$("#core").val("true");
        	$("#save-rule-btn").attr("data-target" , "#save-core-rule-modal");
        } else {
        	$("#core").val("false");
        	$("#save-rule-btn").attr("data-target" , "#save-custom-rule-modal");
        }
    });
}

function addMessage(event) {
	const index = $(".messages-tbody tr").length;
	const message = $(".messages-tbody").append("<tr>"
		+ "<td class='px-1'>"
		+ "<input type='text' class='form-control' form='run-rule-form' name='messages["+index +"].key' placeholder='Message ID'/>"
		+ "</td>"
		+ "<td class='px-1'>"
		+ "<input type='text' class='form-control' form='run-rule-form' name='messages["+index+"].value' placeholder='Message Value'/>"
		+ "</td>"
		+ "<td class='px-1 text-center'>"
		+ "<button class='btn btn-small btn-outline-danger px-1 py-1 delete-message'>"
		+ "<i class='material-icons md-24'>delete</i>"
		+ "</button>"
		+ "</td>"
		+ "</tr>");
	// Reconfigure buttons to delete messages
    $(".delete-message").on("click", deleteMessage);
}

function deleteMessage(event) {
	// Get row of delete button
	const row = $(event.target).closest("tr");
	// Update indices of messages after this one
	row.nextAll("tr").find("input").each(updateMessageIndices);
	// Delete row of delete button
	row.remove();
}

function updateMessageIndices(i, input) {
	const name = input.name;
	const oldIndex = name.split("[")[1].split("]")[0];
	const newIndex = oldIndex - 1;
	$(input).attr("name", name.replace("["+oldIndex+"]", "["+newIndex+"]"));
}

function configureCustomRuleModal(createFunctionReader) {
	// Configure custom rule modal on open
    $('#save-custom-rule-modal').on('show.bs.modal', function(e) {
    	$(".save-custom-messages .messages-table").remove();
    	$(".messages-table").clone().appendTo(".save-custom-messages");
    	$(".save-custom-messages input").prop("readOnly", true);
    	$(".save-custom-messages input").attr("form", "save-custom-rule-form");
    	$(".save-custom-messages tr").each(function (i, tr) {
    		$(tr).children().last().remove();
    	});
    	let createFunction = $("#createFunction").val();
    	createFunctionReader.setValue(createFunction);
    	let sourceCode = $("#sourceCode").val();
		$("#customSourceCode").val(sourceCode);
	});

	// Solves issue where CodeMirror does not display when modal is opened
	$('#save-custom-rule-modal').on('shown.bs.modal', function(e) {
		createFunctionReader.refresh();
	});
}

function configureCoreRuleModal() {
	// Configure core rule modal on open
    $('#save-core-rule-modal').on('show.bs.modal', function(e) {
    	$(".save-core-messages").empty();
    	$(".messages-table input").clone().appendTo(".save-core-messages");
    	$(".save-core-messages input").prop("type", "hidden");
    	$(".save-core-messages input").attr("form", "save-core-rule-form");
        let name = $("#name").val();
        $("#coreName").val(name);
        let sourceCode = $("#sourceCode").val();
        $("#coreSourceCode").val(sourceCode);
        let createFunction = $("#createFunction").val();
        $("#coreCreateFunction").val(createFunction);
    });
}
