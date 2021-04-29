$(document).ready(function() {
    $('[data-toggle="popover"]').popover()

    var editor = CodeMirror.fromTextArea(document.getElementById('code'), {
        lineNumbers: true
    });
    editor.setSize("100%", null);
	
	$('#saveJsonRuleModal').on('show.bs.modal', function(e) {
	    let query = $("#jsonquery").val();
	    let source = editor.getValue();
	    $("#formSource").val(source);
	    $("#ruleQuery").val(query);
	  });
});
