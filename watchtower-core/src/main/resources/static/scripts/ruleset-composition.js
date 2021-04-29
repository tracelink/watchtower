$(document).ready(function() {
	$('#rulesetselect').on('change', function(e) {
		let ruleset = e.target.value;
		$('.rulesCard').hide();
		$("div[id='" + ruleset + "-rules']").show();
	});
	$('#editRulesModal').on('show.bs.modal', function(e) {
		let target = $(e.relatedTarget);
		let action = target.data('action');
		let id = target.data('id');
		let name = target.data('name');
		let ruleIds = target.data('rules');
		$("#rulesPicker").children().attr("selected", false);
		$("#rulesPicker").children("option").each(function() {
			if (ruleIds.includes(parseInt(this.value))) {
				$(this).attr("selected", true);
			}
		});
		$("#rulesPicker").selectpicker("refresh");
		$("#editRulesModalName").html(name);
		$("#editRulesModalForm").attr("action", action);
		$("#editRulesModalInput").attr("name", "rulesetId");
		$("#editRulesModalInput").attr("value", id);
	});
	$('#downloadExample').on('click', function(){
		let ruleType = $('#importRuleType').val()
		$('#exampleType').val(ruleType);
	})
});
