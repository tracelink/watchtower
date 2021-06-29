$(document).ready(function() {
	const datetimeopts = {
			month: 'short', 
			day:'2-digit',
			year:'numeric',
			hour: '2-digit',
			minute: '2-digit',
			second:'2-digit'
		};
	$('.localizetime').html(function(i, html){
		if(isNaN(html)){
			return html;
		}
		return luxon.DateTime.fromMillis(Number(html)).toLocaleString(datetimeopts);
	});
});