$(document).ready(function() {
	$('#rulesetselect').on('change', function(e) {
		let rulesetid = e.target.value;
		$(location).attr('href','/rulesets/'+rulesetid+'/')
	});
});
