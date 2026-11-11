window.WatchtowerScanViolationsLineChart = class WatchtowerScanViolationsLineChart {
	constructor(selectId, canvasId, scanType){
		this.selectId = selectId;
		this.canvasId = canvasId;
		this.scanType = scanType;
		this.scansViosLine = null;
	};	
	
	updateLineData = function(scans, violations) {
		const labels = scans.labels;
		const sCounts = scans.counts;
		const vCounts = violations.counts
		
		// Solves bug where old data flashes on chart
		if (this.scansViosLine != null) {
			this.scansViosLine.destroy();
		}
		
		// Hide chart if there is no data
		let hide = true;
		for (let i = 0; i < labels.length; i++) {
			if (sCounts[i] != 0 || vCounts[i] != 0) {
				hide = false;
				break;
			}
		}
		toggleChart(hide, 'line-no-data', this.canvasId);
		
		var data = {
			datasets: [{
				label: 'Scans Completed',
				yAxisID: "scans-axis", 
				borderColor: '#4687E8',
				backgroundColor: '#4687E8',
				fill: false,
				data: sCounts
			}, {
				label: 'Violations Found',
				yAxisID: "vios-axis", 
				borderColor: '#11B665',
				backgroundColor: '#11B665',
				fill: false,
				data: vCounts
			}],
			labels: labels
		};
	
		var options = {
			plugins: {
				legend: {
					position: 'top',
					labels: {
						 padding: 10,
						 boxWidth: 15
					}
				},
				tooltip: {
					mode: 'index',
					position: 'nearest'
				}
			},
			// Uncomment the following line in order to disable the animations.
			// animation: false,
			scales: {
				'scans-axis': {
					display: true,
					type: 'linear',
					position: 'right',
					grid: {
						display: false
					},
					ticks: {
						beginAtZero: true
					}
				},
				'vios-axis': {
					display: true,
					type: 'linear',
					position: 'left',
					ticks: {
						beginAtZero: true
					}
				}
			},
			layout: {
		        padding: {
		            left: 10,
		            right: 10
		        }
		    }
		};
	
		var ctx = document.getElementById(this.canvasId).getContext('2d');
	
		// Generate the users by device chart.
		this.scansViosLine = new Chart(ctx, {
			type: 'line',
			data: data,
			options: options
		});
	};
	
	updateLineTimePeriod = async (event) => {
		let period = event.target.value;
		wtSetChartLoading('line-no-data', 'Loading scan trend…');
		try {
			const query = wtMetricQuery(this.selectId, period);
			const scansResult = await wtFetchMetric(`/rest/metrics/scans-by-period?${query}&type=${this.scanType}`);
			const violationsResult = await wtFetchMetric(`/rest/metrics/violations-by-period?${query}&type=${this.scanType}`);
			this.updateLineData(scansResult, violationsResult);
		} catch (error) {
			toggleChart(true, 'line-no-data', this.canvasId, error.message);
		}
	};
	
	lineContentLoad = async () => {
		const select = document.getElementById(this.selectId);
		await this.updateLineTimePeriod({target: {value: select.value || 'last-thirty-days'}});
		select.addEventListener('change', this.updateLineTimePeriod);
	};
};
