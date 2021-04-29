$(document).ready(function() {
	$('#deleteModal').on('show.bs.modal', function(e) {
		var key = $(e.relatedTarget).data('key');
		var label = $(e.relatedTarget).data('label');
		$("#deleteKey").text(key);
		$("#deleteLabel").text(label);
		$("#deleteFormKey").attr("value", key);
	});
});

