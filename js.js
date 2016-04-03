/**
 * Load byte array from URL: https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/Sending_and_Receiving_Binary_Data
 *
 * aircrack-ng sample WPA file: http://www.aircrack-ng.org/doku.php?id=wpa_capture
 * Parsing .cap files: http://systemsarchitect.net/2014/03/12/parsing-binary-data-in-php-on-an-example-with-the-pcap-format/
 *
 */
function Packets(data) {
    this.global_header = GlobalHeader(data.substring(0, 24));

    this.frames = [];

    var packet_start = 24;
    while (packet_start < data.length) {
        var ph = PacketHeader(data.substring(packet_start, packet_start + 16));

        packet_start += 16;
        var pf = new PacketFrame(data.substring(packet_start, packet_start + ph.incl_len));
        this.frames.push(pf);

        packet_start += ph.incl_len;
    }
    return this;
}

function dataToInt(data, start, end, big_endian, signed) {
    var result = 0;
    if (big_endian) {
        for (var i = start; i < end; i++) {
            result = result << 8;
            var x = data.charCodeAt(i);
            result = result | x;
        }
    } else {
        for (var i = end - 1; i >= start; i--) {
            result = result << 8;
            var x = data.charCodeAt(i);
            result = result | x;
        }
    }

    if (!signed) {
        return (result >>> 0);
    }
    else {
        return result;
    }
}

function GlobalHeader(data) {
    return {
      "magic_number":  dataToInt(data, 0, 4, true),
      "version_major": dataToInt(data, 4, 6),
      "version_minor": dataToInt(data, 6, 8),
      "thiszone":      dataToInt(data, 8,12, false, true),
      "sigfigs":       dataToInt(data, 12,16),
      "snaplen":       dataToInt(data, 16,20),
      "network":       dataToInt(data, 20,24),
    }
}

function PacketHeader(data) {
    return {
      "ts_sec":   dataToInt(data, 0, 4),
      "ts_usec":  dataToInt(data, 4, 8),
      "incl_len": dataToInt(data, 8,12),
      "orig_len": dataToInt(data,12,16),
    }
}

function PacketFrame(data) {
    // Frame Control
    var fc = dataToInt(data, 0, 1);
    this.fc_version = (fc >>> 0) & 0b11;
    this.fc_type    = (fc >>> 2) & 0b11;
    this.fc_subtype = (fc >>> 4);
    // FrameControl Flags
    var fcf = dataToInt(data, 1, 2);
    this.fcf_toDS          = !!(fcf >>> 0);
    this.fcf_fromDS        = !!(fcf >>> 1);
    this.fcf_moreFragments = !!(fcf >>> 2);
    this.fcf_retry         = !!(fcf >>> 3);
    this.fcf_pwrMgt        = !!(fcf >>> 4);
    this.fcf_moreData      = !!(fcf >>> 5);
    this.fcf_protected     = !!(fcf >>> 6);
    this.fcf_order         = !!(fcf >>> 7);

    this.duration = dataToInt(data, 2, 4);

    this.addr_destination = dataToInt(data, 4, 10).toString(16);
    this.addr_source      = dataToInt(data, 10, 16).toString(16);

    this.bssid = dataToInt(data, 16, 22).toString(16);

    var frag_seq = dataToInt(data, 22, 24);
    this.fragment_number = (frag_seq >>> 0) & 0b1111;
    this.sequence_number = (frag_seq >>> 4) & 0b111111111111;

    // Parse remaining data in frame.
    var frame_data = data.substring(24);
    if        (this.fc_version == 0
            && this.fc_type == 0
            && this.fc_subtype == 8) {
        this.type = "BeaconFrame";
        this.data = new BeaconFrame(frame_data);

    } else if (this.fc_version == 0
            && this.fc_type == 0
            && this.fc_subtype == 5) {
        this.type = "ProbeResponse";
        this.data = new BeaconFrame(frame_data);

    } else if (this.fc_version == 0
            && this.fc_type == 0
            && this.fc_subtype == 4) {
        this.type = "ProbeRequest";

    } else if (this.fc_version == 0
            && this.fc_type == 0
            && this.fc_subtype == 11) {
        this.type = "Authentication";
        this.data = new AuthenticationFrame(frame_data);

    } else if (this.fc_version == 0
            && this.fc_type == 0
            && this.fc_subtype == 0) {
        this.type = "AssociationRequest";

    } else if (this.fc_version == 0
            && this.fc_type == 0
            && this.fc_subtype == 1) {
        this.type = "AssociationResponse";

    } else {
        //throw Error("Unexpected frame, version:", this.fc_version, "type:", this.fc_type, "subtype:", this.fc_subtype);
    }

    return this;
}

function bytesToHex(data) {
    var debug = "raw data (" + data.length + " bytes)\n";
    for (var i = 0; i < data.length; i++) {
        var b = data.charCodeAt(i).toString(16);
        if (b.length == 1) {
            b = "0" + b;
        }
        debug += "" + b + " ";
        if (i > 0 && (i + 1) % 8 == 0) {
            debug += "  ";
        }
        if (i > 0 && (i + 1) % 16 == 0) {
            debug += "\n";
        }
    }
    return debug;
}
        
function BeaconFrame(data) {
    var fixed_params = data.substring(0, 12);
    // TODO: Parse fixed params

    data = data.substring(12);
    this.tags = {};
    while (data.length > 0) {
        var tag = {};
        var tag_number = dataToInt(data, 0, 1);
        var tag_length = dataToInt(data, 1, 2);
        var tag_data = data.substring(2, 2 + tag_length);
        if (tag_number == 0) {
            // SSID
            tag.ssid = tag_data;
            this.tags[tag_number] = tag;
        }
        data = data.substring(2 + tag_length);
    }
    return this;
}

function AuthenticationFrame(data) {
    var fixed_params = data.substring(0, 6);

    this.auth_algorithm = dataToInt(data, 0, 2);
    this.auth_seq = dataToInt(data, 2, 4);
    this.status_code = dataToInt(data, 4, 6);
    return this;
}

document.querySelector('input').addEventListener('change', function() {
    var reader = new FileReader();
    reader.onload = function(){
        var packets = new Packets(this.result);
        console.log("done", packets);
        document.querySelector('#result').innerHTML = JSON.stringify(packets, null, 2);
    }
    reader.readAsBinaryString(this.files[0]);
}, false);

