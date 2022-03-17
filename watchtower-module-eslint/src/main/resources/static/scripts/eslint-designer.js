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

    // Configure button to add message
    $(".add-message").on("click", addMessage);

    // Configure buttons to delete messages
    $(".delete-message").on("click", deleteMessage);

	// Configure save rule modals
	configureCustomRuleModal(createFunctionReader);
	configureCoreRuleModal();
});

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
    $('#save-rule-modal').on('show.bs.modal', function(e) {
    	$(".save-messages .messages-table").remove();
    	$(".messages-table").clone().appendTo(".save-messages");
    	$(".save-messages input").prop("readOnly", true);
    	$(".save-messages input").attr("form", "save-rule-form");
    	$(".save-messages tr").each(function (i, tr) {
    		$(tr).children().last().remove();
    	});
    	let createFunction = $("#createFunction").val();
    	createFunctionReader.setValue(createFunction);
    	let sourceCode = $("#sourceCode").val();
		$("#customSourceCode").val(sourceCode);
	});

	// Solves issue where CodeMirror does not display when modal is opened
	$('#save-rule-modal').on('shown.bs.modal', function(e) {
		createFunctionReader.refresh();
	});
}

