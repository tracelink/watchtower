$(document).ready(function() {
  $('#rotateKeyModal').on('show.bs.modal', function(e) {
    let target = $(e.relatedTarget);
    let id = target.data('id');
    let name = target.data('name');
    let content = "Are you sure you want to rotate the key for converter \"" + name + "\"?";

    $("#rotateModalContent").html(content);
    $("#rotateModalInput").attr("value", id);
  });
});
