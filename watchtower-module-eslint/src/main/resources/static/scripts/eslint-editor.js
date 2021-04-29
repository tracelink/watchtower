$(document).ready(function() {
    var editor = CodeMirror.fromTextArea(document.getElementById('createFunction'), {
        lineNumbers: true
    });
    editor.setSize(null, 260);
});
