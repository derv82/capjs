/**
 * Load byte array from URL: https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/Sending_and_Receiving_Binary_Data
 *
 * aircrack-ng sample WPA file: http://www.aircrack-ng.org/doku.php?id=wpa_capture
 * Parsing .cap files: http://systemsarchitect.net/2014/03/12/parsing-binary-data-in-php-on-an-example-with-the-pcap-format/
 *
 */

/** Types of understood packet frames. */
var FrameType = {
    "BeaconResponse":true,
    "ProbeRequest":true,
    "ProbeResponse":true,
    "Authentication":true,
    "AssociationResponse":true,
    "EAPOLWpaKey":true
};
    
var Wpa = {};

/** "Constructor" that parses the given data into packets and frames.
 * @param data (string) The data as a string (with charCodes);
 * @return     (Object) Containing 'global_header' (see GlobalHeader)
 *                      and 'frames' (array of *Frame objects); 
 */
Wpa.parse = function(data) {
    var global_header = Wpa.GlobalHeader(data.substring(0, 24));

    var frames = [];

    var packet_start = 24;
    while (packet_start < data.length) {
        var ph = Wpa.PacketHeader(data.substring(packet_start, packet_start + 16));

        packet_start += 16;
        var pf = Wpa.PacketFrame(data.substring(packet_start, packet_start + ph.incl_len));
        frames.push(pf);

        packet_start += ph.incl_len;
    }
    return {
        "global_header": global_header,
        "frames": frames
    };
};

/**
 * Converts subsection of 'data' into an integer.
 * @param data       (string) The data as a string (with charCodes).
 * @param start      (int)    The starting index of the subsection.
 * @param end        (int)    The ending index of the subsection.
 * @param big_endian (bool)   If data is in big-endian format, default: false
 * @param signed     (bool)   If int should be signed, default: false.
 * @return           (int)    Integer-representation of the subsection of data.
 */
Wpa.dataToInt = function(data, start, end, big_endian, signed) {
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
};

/**
 * For debugging purposes only.
 * @return Debug string including the data length and pretty-printed hex values.
 */
Wpa.bytesToHex = function(data) {
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
};

/**
 * The capture file's "Global Header".
 * TODO: Check magic_number to see what endian-ness we should be using.
 */
Wpa.GlobalHeader = function(data) {
    return {
      "magic_number":  Wpa.dataToInt(data, 0, 4, true),
      "version_major": Wpa.dataToInt(data, 4, 6),
      "version_minor": Wpa.dataToInt(data, 6, 8),
      "thiszone":      Wpa.dataToInt(data, 8,12, false, true),
      "sigfigs":       Wpa.dataToInt(data, 12,16),
      "snaplen":       Wpa.dataToInt(data, 16,20),
      "network":       Wpa.dataToInt(data, 20,24),
    };
};

/**
 * Header for a single packet.
 * Contains vital "incl_len" which is the length of the packet data.
 */
Wpa.PacketHeader = function(data) {
    return {
      "ts_sec":   Wpa.dataToInt(data, 0, 4),
      "ts_usec":  Wpa.dataToInt(data, 4, 8),
      "incl_len": Wpa.dataToInt(data, 8,12),
      "orig_len": Wpa.dataToInt(data,12,16),
    };
};

/**
 * Packet frame information.
 * If frame is identified, will contain a "type" (string) representing the frame.
 */
Wpa.PacketFrame = function(data) {
    // Frame Control
    var result = {};
    var fc = Wpa.dataToInt(data, 0, 1);
    result.fc_version = (fc >>> 0) & 0b11;
    result.fc_type    = (fc >>> 2) & 0b11;
    result.fc_subtype = (fc >>> 4);
    // FrameControl Flags
    var fcf = Wpa.dataToInt(data, 1, 2);
    result.fcf_toDS          = !!(fcf >>> 0);
    result.fcf_fromDS        = !!(fcf >>> 1);
    result.fcf_moreFragments = !!(fcf >>> 2);
    result.fcf_retry         = !!(fcf >>> 3);
    result.fcf_pwrMgt        = !!(fcf >>> 4);
    result.fcf_moreData      = !!(fcf >>> 5);
    result.fcf_protected     = !!(fcf >>> 6);
    result.fcf_order         = !!(fcf >>> 7);

    result.duration = Wpa.dataToInt(data, 2, 4);

    result.addr_destination = Wpa.dataToInt(data, 4, 10).toString(16);
    result.addr_source      = Wpa.dataToInt(data, 10, 16).toString(16);

    result.bssid = Wpa.dataToInt(data, 16, 22).toString(16);

    var frag_seq = Wpa.dataToInt(data, 22, 24);
    result.fragment_number = (frag_seq >>> 0) & 0b1111;
    result.sequence_number = (frag_seq >>> 4) & 0b111111111111;

    // Parse remaining data in frame.
    var frame_data = data.substring(24);
    if        (result.fc_version == 0
            && result.fc_type == 0
            && result.fc_subtype == 8) {
        result.type = "BeaconResponse";
        result.data = Wpa.BeaconFrame(frame_data);

    } else if (result.fc_version == 0
            && result.fc_type == 0
            && result.fc_subtype == 5) {
        result.type = "ProbeResponse";
        result.data = Wpa.BeaconFrame(frame_data);

    } else if (result.fc_version == 0
            && result.fc_type == 0
            && result.fc_subtype == 4) {
        result.type = "ProbeRequest";

    } else if (result.fc_version == 0
            && result.fc_type == 0
            && result.fc_subtype == 11) {
        result.type = "Authentication";
        result.data = Wpa.AuthenticationFrame(frame_data);

    } else if (result.fc_version == 0
            && result.fc_type == 0
            && result.fc_subtype == 0) {
        result.type = "AssociationRequest";

    } else if (result.fc_version == 0
            && result.fc_type == 0
            && result.fc_subtype == 1) {
        result.type = "AssociationResponse";

    } else if (result.fc_version == 0
            && result.fc_type == 2 // Data Frame
            && result.fc_subtype == 0) {
        result.type = "EAPOLWpaKey";
        result.data = Wpa.eapolWpaKey(frame_data);

    } else {
        //throw Error("Unexpected frame, version:", result.fc_version, "type:", result.fc_type, "subtype:", result.fc_subtype);
    }

    return result;
};

Wpa.BeaconFrame = function(data) {
    var result = {};
    var fixed_params = data.substring(0, 12);
    // TODO: Parse fixed params

    data = data.substring(12);
    result.tags = {};
    while (data.length > 0) {
        var tag = {};
        var tag_number = Wpa.dataToInt(data, 0, 1);
        var tag_length = Wpa.dataToInt(data, 1, 2);
        var tag_data = data.substring(2, 2 + tag_length);
        if (tag_number == 0) {
            // SSID
            tag.ssid = tag_data;
            result.tags[tag_number] = tag;
        }
        data = data.substring(2 + tag_length);
    }
    return result;
};

Wpa.AuthenticationFrame = function(data) {
    var reuslt = {};

    var fixed_params = data.substring(0, 6);

    result.auth_algorithm = Wpa.dataToInt(data, 0, 2);
    result.auth_seq = Wpa.dataToInt(data, 2, 4);
    result.status_code = Wpa.dataToInt(data, 4, 6);
    return result;
};

Wpa.eapolWpaKey = function(data) {

};
