$(document).ready(function() {
	$('#rulesetselect').on('changed.bs.select', function(e) {
		let ruleset = this.value;
		$('.rulesetRow').hide();
		$("div[id='" + ruleset + "-row']").show();
	});
	
	$('#createRulesetModal').on('show.bs.modal', function(e) {
		let target = $(e.relatedTarget);
		let action = target.data('action');
		$("#createModalForm").attr("action", action);
	});
	
	$('#defaultRulesetModal').on('show.bs.modal', function(e) {
		let target = $(e.relatedTarget);
		let action = target.data('action');
		$("#defaultModalForm").attr("action", action);
	});
});

$(document).ready(function() {
	$('#deleteRulesetModal').on('show.bs.modal', function(e) {
		let target = $(e.relatedTarget);
		let action = target.data('action');
		let id = target.data('id');
		let name = target.data('name');
		$("#deleteModalName").html(name);
		$("#deleteModalForm").attr("action", action);
		$("#deleteModalInput").attr("name", "rulesetId");
		$("#deleteModalInput").attr("value", id);
	});
});