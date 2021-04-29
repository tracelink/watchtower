$(document).ready(function() {
    $('[data-toggle="popover"]').popover()

    var editor = CodeMirror.fromTextArea(document.getElementById('source'), {
        lineNumbers: true
    });
	
	$('#saveRegexRuleModal').on('show.bs.modal', function(e) {
	    let query = $("#regexquery").val();
	    let source = editor.getValue();
	    $("#formSource").val(source);
	    $("#ruleQuery").val(query);
	  });
});