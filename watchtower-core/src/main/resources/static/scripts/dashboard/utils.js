const toggleChart = (hide, none, canvas) => {
	if (hide) {
		document.getElementById(none).innerHTML = 'No data to display.';
		document.getElementById(canvas).style.display = 'none';
	} else {
		document.getElementById(none).innerHTML = '';
		document.getElementById(canvas).style.display = 'block';
	}
};

const getColors = (numColors) => {
	// Note that the colors will wrap after (baseColors.length) * 6 distinct rules
	let baseColors = [
		'rgba(0,63,156,t)',
		'rgba(236,149,0,t)',
		'rgba(211,211,211,t)',
		'rgba(92,145,31,t)',
		'rgba(52,101,172,t)',
		'rgba(246,196,111,t)',
		'rgba(242,242,242,t)',
		'rgba(102,168,33,t)',
		'rgba(70,135,232,t)',
		'rgba(177,128,44,t)',
		'rgba(37,37,37,t)',
		'rgba(135,196,67,t)',
		'rgba(190,216,254,t)',
		'rgba(154,97,0,t)',
		'rgba(113,113,113,t)',
		'rgba(206,245,102,t)',
		'rgba(0,94,232,t)',
		'rgba(246,178,61,t)',
		'rgba(136,136,136,t)',
		'rgba(17,182,101,t)',
		'rgba(0,42,105,t)',
		'rgba(255,255,248,t)',
		'rgba(177,177,177,t)',
		'rgba(0,182,92,t)'
	];
	
	let transparencies = [1, 0.85, 0.7, 0.55, 0.4, 0.25];
	let graphColors = [];
	
	let i = 0;
	let j = 0;
	
	while (graphColors.length < numColors) {
		graphColors.push(baseColors[j].replace('t', transparencies[i]));
		
		// If we have gone through all the colors of this transparency, restart base 
		// colors and go to next transparency
		if (j == baseColors.length - 1) {
			j = 0;
			i += 1;
		} else {
			// Just increment to next base color at this transparency
			j += 1;
		}
		
		// If we run out of colors, wrap back to the beginning
		if (i == transparencies.length) {
			i = 0;
		} 
	}
	
	return graphColors;
};