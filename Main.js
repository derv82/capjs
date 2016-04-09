document.querySelector('input').addEventListener('change', function() {
    var reader = new FileReader();
    reader.onload = function(){
        var capfile = new CapFile(this.result, true);
        capfile.extractPmkFields();
        document.querySelector('#result').innerHTML = JSON.stringify(capfile, null, 2);
    }
    reader.readAsBinaryString(this.files[0]);
}, false);

