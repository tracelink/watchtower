class WatchtowerViolationsPieChart {
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
				hoverBorderColor: '#ffffff',
				data: counts,
				backgroundColor: getColors(labels.length)
			}],
			labels: labels
		};
	
		var options = {
			legend: {
				position: 'right',
				labels: {
					 padding: 5,
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
			
		const response = await fetch(`/rest/metrics/violations-by-type?period=${period}&type=${this.scanType}`);
		const result = await response.json();
		this.updatePieData(result);
	};
	
	pieContentLoad = async () => {
		const response = await fetch(`/rest/metrics/violations-by-type?period=last-four-weeks&type=${this.scanType}`);
		const result = await response.json();
		this.updatePieData(result);
	
		$('#'+this.selectId).change(this.updatePieTimePeriod);
	};
}