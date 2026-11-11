window.WatchtowerViolationsPieChart = class WatchtowerViolationsPieChart {
	constructor(selectId, canvasId, scanType){
		this.selectId = selectId;
		this.canvasId = canvasId;
		this.scanType = scanType;
		this.viosPie = null;
	};
	
	updatePieData = function(result) {
		const labels = result.labels;
		const counts = result.counts;
		
		// Solves bug where old data flashes on chart
		if (this.viosPie != null) {
			this.viosPie.destroy();
		}
		
		// Hide chart if there is no data
		toggleChart(labels.length == 0, 'pie-no-data', this.canvasId);
		
		var data = {
			datasets: [{
				// Item 10.14: was a hardcoded #ffffff, which drew a white halo around the
				// hovered slice on a dark background.
				hoverBorderColor: wtThemeValue('--wt-surface', '#ffffff'),
				data: counts,
				backgroundColor: getColors(labels.length)
			}],
			labels: labels
		};
	
		var options = {
			plugins: {
				legend: {
					position: 'right',
					labels: {
						 padding: 5,
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
			layout: {
		        padding: {
		            left: 10,
		            right: 10
		        }
		    }
		};
	
		var ctx = document.getElementById(this.canvasId).getContext('2d');
	
		// Generate the users by device chart.
		this.viosPie = new Chart(ctx, {
			type: 'pie',
			data: data,
			options: options
		});
	};
	
	updatePieTimePeriod = async (event) => {
		let period = event.target.value;
		wtSetChartLoading('pie-no-data', 'Loading finding distribution…');
			
		try {
			const query = wtMetricQuery(this.selectId, period);
			this.updatePieData(await wtFetchMetric(`/rest/metrics/violations-by-type?${query}&type=${this.scanType}`));
		} catch (error) {
			toggleChart(true, 'pie-no-data', this.canvasId, error.message);
		}
	};
	
	pieContentLoad = async () => {
		const select = document.getElementById(this.selectId);
		await this.updatePieTimePeriod({target: {value: select.value || 'last-thirty-days'}});
		select.addEventListener('change', this.updatePieTimePeriod);
	};
};
