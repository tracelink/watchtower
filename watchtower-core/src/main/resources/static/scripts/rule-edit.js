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
});