$(document).ready(function() {
	var adTable = $("#advisoryTable").DataTable({
		ajax : {
			url : '/rest/advisory',
			dataSrc : 'advisories'
		},
		columns : [ {
			"title" : "Advisory Id",
			"data" : "advisoryName"
		}, {
			"title" : "Score",
			"data" : "score"
		}, {
			"title" : "Description",
			"data" : "description"
		}, {
			"title" : "Link",
			"data" : "uri",
			"render" : function(data, type, row, meta) {
				if (type === 'display') {
					data = '<a target="_blank" href="' + data + '">' + data + '</a>';
				}
				return data;
			}
		}, {
			"title": "Whitelist",
			"data" : "advisoryName",
			"render": function(data, type, row, meta) {
				return '<button class="ml-auto btn btn-success" data-toggle="modal" data-target="#saveAdvisoryRuleModal" data-name="'+data+'">Add to Whitelist</button>';
			}
		} ]
	});

	$('#saveAdvisoryRuleModal').on('show.bs.modal', function(e) {
		var name = $(e.relatedTarget).data('name');
	    $("#advisoryName").attr("value", name);
	  });
});
