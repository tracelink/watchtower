$(document).ready(function() {
  $('#scmidbtn').children().on('click', function(e) {
    var id = this.children[0].id;
    $('.reposTable').addClass('d-none');
    $("div[id='"+id+"']").removeClass('d-none');
  });
});