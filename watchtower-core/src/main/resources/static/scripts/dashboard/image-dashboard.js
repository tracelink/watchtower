$(document).ready(function() {
	var pieChart = new WatchtowerViolationsPieChart(
			'pie-period', 
			'violations-pie',
			'container');
	pieChart.pieContentLoad();
	
	var barChart = new WatchtowerViolationsBarChart(
			'bar-period',
			'violations-bar',
			'container');
	barChart.barContentLoad();
	
	var lineChart = new WatchtowerScanViolationsLineChart(
			'line-period',
			'scans-vios-line',
			'container');
	lineChart.lineContentLoad();
});