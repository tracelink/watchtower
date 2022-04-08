$(document).ready(function() {
	var pieChart = new WatchtowerViolationsPieChart(
			'pie-period', 
			'violations-pie',
			'advisory');
	pieChart.pieContentLoad();
	
	var barChart = new WatchtowerViolationsBarChart(
			'bar-period',
			'violations-bar',
			'advisory');
	barChart.barContentLoad();
	
	var lineChart = new WatchtowerScanViolationsLineChart(
			'line-period',
			'scans-vios-line',
			'advisory');
	lineChart.lineContentLoad();
});