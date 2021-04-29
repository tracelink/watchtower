$(document).ready(function() {
	$('[data-toggle="popover"]').popover()

    var editor = CodeMirror.fromTextArea(document.getElementById('source'), {
        lineNumbers: true
    });
	
  $('#savePmdRuleModal').on('show.bs.modal', function(e) {
    let query = $("#xpathquery").val();
    let language = $("#queryLanguage option").filter(":selected").val();
    let source = editor.getValue();
    $("#formSource").val(source);
    $("#ruleQuery").val(query);
    $('#ruleLanguage option[value='+language+']').prop("selected", true);
  });
});