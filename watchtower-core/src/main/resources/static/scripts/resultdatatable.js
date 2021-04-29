$(document).ready(function() {
	$("table.datatable").DataTable();
	$("table.datatable-invert").DataTable({
		"order": [[0, 'desc']]
	});
	$("table.datatable-clean").DataTable({
		paging: false
	});
});
