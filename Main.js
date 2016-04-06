document.querySelector('input').addEventListener('change', function() {
    var reader = new FileReader();
    reader.onload = function(){
        var wpa = new CapFile(this.result, true);
        console.log("done", wpa);
        document.querySelector('#result').innerHTML = JSON.stringify(wpa, null, 2);
    }
    reader.readAsBinaryString(this.files[0]);
}, false);
