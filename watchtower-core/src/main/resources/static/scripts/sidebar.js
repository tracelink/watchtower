$(document).ready(function() {
	var path = window.location.pathname;
    var navlink;

    while(navlink == undefined && path !== ""){
    	navlink = $('aside li>a[href="'+ path +'"]')[0];
    	path = path.substring(0, path.lastIndexOf('/'));
    }
	/* mark the nav item active to highlight it */
	$(navlink).addClass("active");

	/* mark the nav's collapsed parent to show */
	let collapsed = $(navlink).parents("div.collapse")[0];
	$(collapsed).addClass("show");
});
