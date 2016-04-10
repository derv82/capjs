document.querySelector('input').addEventListener('change', function() {
    var reader = new FileReader();
    reader.onload = function(){
        var capfile = new CapFile(this.result, true);
        document.querySelector('#result').innerHTML = JSON.stringify(capfile, null, 2);
        var handshake = capfile.extractPmkFields();
        /*
        handshake = {
            ssid: "Tribble",
            bssid: "002275ecf9c9",
            snonce: "da12c942e9dfcbe67068438f87cd4ce49b2…",
            anonce: "f5f5cd2ca691efe420224f466d3eb1633ef…",
            srcAddress: "f4ce46629c64",
            dstAddress: "002275ecf9c9",
            replayCounter: 2925,
            mic: "646debf34b677fbfd78c5724dc9ea442"
        }

        // Handshake data from http://stackoverflow.com/questions/12018920/wpa-handshake-with-python-hashing-difficulties
        // TODO: Remove, this is purely for testing.
        handshake = {
            ssid: "Netgear 2/158",
            bssid: "001e2ae0bdd0",
            snonce: "60eff10088077f8b03a0e2fc2fc37e1fe1f30f9f7cfbcfb2826f26f3379c4318",
            anonce: "61c9a3f5cdcdf5fae5fd760836b8008c863aa2317022c7a202434554fb38452b",
            srcAddress: "001e2ae0bdd0",
            dstAddress: "cc08e0620bc8",
            mic: "45282522bc6707d6a70a0317a3ed48f0",
            keyLength: 32,
            keyDescriptorVersion: 1,
            eapolFrameBytes: "0103005ffe01090020000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            // PSK is 10zZz10ZZzZ
        }
        */

        var c = new Crack(handshake);

        var pmk = c.pmk("dandelion");
        //var pmk = c.pmk("10zZz10ZZzZ");
        console.log("PMK", pmk.toString());

        var ptk = c.ptk(pmk);
        console.log("PTK", ptk);
        c.ptkToMic(ptk);
    }
    reader.readAsBinaryString(this.files[0]);
}, false);

