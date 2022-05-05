$(document).ready(function() {
  $('#statsbtn').children().on('click', function(e) {
    var id = this.children[0].id;
    $('.statscards').addClass('d-none');
    $("div[id='"+id+"']").removeClass('d-none');
  });
});