$(document).ready(function() {
  $('#rulesetbtn').children().on('click', function(e) {
    var id = this.children[0].id;
    $('.rulesTable').hide();
    $("table[id='"+id+"']").show();
  });
});