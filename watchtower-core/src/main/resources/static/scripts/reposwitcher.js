$(document).ready(function() {
  $('#scmidbtn').children().on('click', function(e) {
    var id = this.children[0].id;
    $('.reposTable').hide();
    $("div[id='"+id+"']").show();
  });
});