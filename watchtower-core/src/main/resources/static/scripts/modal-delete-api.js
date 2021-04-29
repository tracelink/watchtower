$(document).ready(function() {
	$('#deleteModal').on('show.bs.modal', function(e) {
		var label = $(e.relatedTarget).data('label');
		$("#modalApiLabel").attr("value", label);
	});
});
