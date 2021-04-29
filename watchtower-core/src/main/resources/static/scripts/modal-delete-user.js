$(document).ready(function() {
	$('#myModal').on('show.bs.modal', function(e) {
		var id = $(e.relatedTarget).data('id');
		$(".deleteuser").attr("value", id);
	});
});
