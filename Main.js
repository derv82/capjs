document.querySelector('input').addEventListener('change', function() {
    var reader = new FileReader();
    reader.onload = function(){
        var packets = new Wpa.parse(this.result);
        console.log("done", packets);
        document.querySelector('#result').innerHTML = JSON.stringify(packets, null, 2);
    }
    reader.readAsBinaryString(this.files[0]);
}, false);
