window.WatchtowerViolationsBarChart = class WatchtowerViolationsBarChart {
	constructor(selectId, canvasId, scanType){
		this.selectId = selectId;
		this.canvasId = canvasId;
		this.scanType = scanType;
		this.viosBar = null;
	};	
	
	updateBarData = function(result) {
		const labels = result.labels;
		
		// Solves bug where old data flashes on chart
		if (this.viosBar != null) {
			this.viosBar.destroy();
		}
		
		// Pull out datasets and hide chart if there is no data
		let sets = [];
		let hide = true;
		let colorIndex = 0;
		const colors = getColors(Object.keys(result).length - 1);
		
		for (var key in result) {
			if (key == "labels") {
				continue;
			}
			// Add set to datasets
			let set = {
				label: key,
				borderColor: colors[colorIndex],
				backgroundColor: colors[colorIndex],
				fill: false,
				data: result[key]
			}
			sets.push(set);
		
			for (let i = 0; i < labels.length; i++) {
				if (result[key][i] != 0) {
					hide = false;
					break;
				}
			}
			colorIndex += 1
		}
		// Hide chart if no data
		toggleChart(hide, 'bar-no-data', this.canvasId);
	
		var data = {
			datasets: sets,
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
				x: {
					stacked: true
				},
				y: {
					stacked: true,
					display: true,
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
		this.viosBar = new Chart(ctx, {
			type: 'bar',
			data: data,
			options: options
		});
	};

	updateBarTimePeriod = async (event) => {
		let period = event.target.value;
		wtSetChartLoading('bar-no-data', 'Loading time and type trend…');
			
		try {
			const query = wtMetricQuery(this.selectId, period);
			this.updateBarData(await wtFetchMetric(`/rest/metrics/violations-by-period-and-type?${query}&type=${this.scanType}`));
		} catch (error) {
			toggleChart(true, 'bar-no-data', this.canvasId, error.message);
		}
	};
	
	barContentLoad = async () => {
		const select = document.getElementById(this.selectId);
		await this.updateBarTimePeriod({target: {value: select.value || 'last-thirty-days'}});
		select.addEventListener('change', this.updateBarTimePeriod);
	};
	
	
};
