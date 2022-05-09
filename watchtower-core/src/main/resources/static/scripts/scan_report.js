$(document).ready(function() {
	$('table.datatable td:not(:has(>a))').html(function(i, html){
	    return html.replace(/\//g, '/\u200B');
	});
	$('table.datatable td a').text(function(i, txt){
	    return txt.replace(/\//g, '/\u200B');
	});
});