$(document).ready(function() {
	var pieChart = new WatchtowerViolationsPieChart(
			'pie-period', 
			'violations-pie',
			'pull_request');
	pieChart.pieContentLoad();
	
	var barChart = new WatchtowerViolationsBarChart(
			'bar-period',
			'violations-bar',
			'pull_request');
	barChart.barContentLoad();
	
	var lineChart = new WatchtowerScanViolationsLineChart(
			'line-period',
			'scans-vios-line',
			'pull_request');
	lineChart.lineContentLoad();
});