class WatchtowerScanViolationsLineChart{
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
			legend: {
				position: 'top',
				labels: {
					 padding: 10,
					 boxWidth: 15
				}
			},
			cutoutPercentage: 0,
			// Uncomment the following line in order to disable the animations.
			// animation: false,
			tooltips: {
				custom: false,
				mode: 'index',
				position: 'nearest'
			},
			scales: {
				yAxes: [{
					display: true,
					id: "scans-axis",
					type: 'linear',
					position: 'right',
					gridLines: {
						display: false
					},
					ticks: {
						beginAtZero: true
					}
					
				}, {
					display: true,
					id: "vios-axis",
					type: 'linear',
					position: 'left',
					ticks: {
						beginAtZero: true
					}
				}]
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
			
		const scansResponse = await fetch(`/rest/metrics/scans-by-period?period=${period}&type=${this.scanType}`);
		const scansResult = await scansResponse.json();
		
		const violationsResponse = await fetch(`/rest/metrics/violations-by-period?period=${period}&type=${this.scanType}`);
		const violationsResult = await violationsResponse.json();
		
		this.updateLineData(scansResult, violationsResult);
	};
	
	lineContentLoad = async () => {
		const scansResponse = await fetch(`/rest/metrics/scans-by-period?period=last-four-weeks&type=${this.scanType}`);
		const scansResult = await scansResponse.json();
		
		const violationsResponse = await fetch(`/rest/metrics/violations-by-period?period=last-four-weeks&type=${this.scanType}`);
		const violationsResult = await violationsResponse.json();
		
		this.updateLineData(scansResult, violationsResult);
	
		$('#' + this.selectId).change(this.updateLineTimePeriod);
	};
}