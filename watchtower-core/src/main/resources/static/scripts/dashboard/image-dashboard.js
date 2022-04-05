$(document).ready(function() {
	var pieChart = new WatchtowerViolationsPieChart(
			'pie-period', 
			'violations-pie',
			'upload');
	pieChart.pieContentLoad();
	
	var barChart = new WatchtowerViolationsBarChart(
			'bar-period',
			'violations-bar',
			'upload');
	barChart.barContentLoad();
	
	var lineChart = new WatchtowerScanViolationsLineChart(
			'line-period',
			'scans-vios-line',
			'upload');
	lineChart.lineContentLoad();
});