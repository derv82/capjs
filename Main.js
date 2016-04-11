// Debug
var textArea = document.querySelector("#debug");
textArea.value = "";

function debug(txt) {
    if (textArea.value !== '') {
        textArea.value += "\n";
    }
    textArea.value += txt;
    textArea.scrollTop = textArea.scrollHeight;
}

// FileChooser
document.querySelector('#fileChooser').addEventListener('change', function() {
    var reader = new FileReader();
    reader.onload = function(){
        var capfile = new CapFile(this.result, debug);
        document.querySelector('#result').innerHTML = JSON.stringify(capfile, null, 2);
    }
    reader.readAsBinaryString(this.files[0]);
}, false);

// Test buttons
document.querySelector("#test1").addEventListener('click', function() {
    Crack.test_WPA1(debug);
}, false);
document.querySelector("#test2").addEventListener('click', function() {
    Crack.test_WPA2(debug);
}, false);
