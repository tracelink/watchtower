$(document).ready(function() {
	$('table.datatable td').html(function(i, html){
	    return html.replace(/\//g, '/\u200B');
	});
});