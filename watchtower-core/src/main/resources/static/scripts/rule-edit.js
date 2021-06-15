$(document).ready(function() {
  $('#deleteRuleModal').on('show.bs.modal', function(e) {
    let target = $(e.relatedTarget);
    let action = target.data('action');
    let id = target.data('id');
    let name = target.data('name');
    let rulesets = target.data('rulesets');
    let content = 'This action will remove ' + name + ' from all rulesets. ' + name + rulesets + '. Are you sure you want to delete this rule?';
    $("#deleteModalName").html(name);
    $("#deleteModalContent").html(content);
    $("#deleteModalForm").attr("action", action);
    $("#deleteModalInput").attr("name", "ruleId");
    $("#deleteModalInput").attr("value", id);
  });
  $('.ruleLink').html(function(i, html){
	    return html.replace(/([a-z])([A-Z0-9])/g, '$1\u200B$2')
	    			.replace(/([A-Z])([0-9])/g, '$1\u200B$2')
	    			.replace(/([0-9])([A-Za-z])/g, '$1\u200B$2');
  });
  
  
});