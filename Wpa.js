/**
 * Load byte array from URL: https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/Sending_and_Receiving_Binary_Data
 *
 * aircrack-ng sample WPA file: http://www.aircrack-ng.org/doku.php?id=wpa_capture
 * Parsing .cap files: http://systemsarchitect.net/2014/03/12/parsing-binary-data-in-php-on-an-example-with-the-pcap-format/
 *
 * http://www.willhackforsushi.com/papers/80211_Pocket_Reference_Guide.pdf
 *
 * Details on WPA encryption (byte-level) - http://sid.rstack.org/pres/0810_BACon_WPA2_en.pdf
 *  - Includes details on "caching" repeated calls to "BODY"
 *
 * HMAC-SHA1 in JS - https://github.com/Caligatio/jsSHA/tree/v2.0.1
 *  - Try online: https://caligatio.github.io/jsSHA/
 *  - Text: "value"
 *  - Key: "secret"
 * 
 * PBKDF2:
 *  - Apparently it's HMAC-SHA1() * 8192
 *  - But see https://en.wikipedia.org/wiki/PBKDF2
 *  - PBKDF2, DK = PBKDF2(PRF,       Password,   Salt, count, dkLen)
 *  - WPA,    DK = PBKDF2(HMAC−SHA1, passphrase, ssid,  4096, 256)
 *
 * Details on 802.11 packet structures - http://www.studioreti.it/slide/802-11-Frame_E_C.pdf
 *
 * TODO: 
 *  - Look at using ArrayBuffer + DataView internal JS structures.
 *  - Browser compatibility  (ie, chrome, safari)
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

Wpa.use_big_endian = true;


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
        if (pf.data) {
            frames.push(pf);
        }

        packet_start += ph.incl_len;
    }

    /**
     *  Extract data from handshakes required for cracking.
     */
    var extract = function() {
        // Look for SSID name in previous beacons/auth packets

        // Look for last 3 frames of handshake

        /* Handshake (2 of 4):
         * mic:true
         * ack:false
         * install:false
         * key_data_length > 0 (data !== undefined)
         * 
         * Extract:
         * - SNonce (from STATION)
         */

        /* Handshake (3 of 4):
         * mic:true
         * ack:true
         * install:true
         * 
         * Extract:
         * - src_address (STATION)
         * - dst_address (AP)
         * - ANonce (from AP)
         * - replay_counter (for Handshake 4 of 4)
         */

        /* Handshake (4 of 4):
         * mic:true
         * ack:false
         * install:false
         * replay_couner: <same as Handshake (3 of 4)>
         * (And/Or) key_data_length == 0 (data === undefined)
         * 
         * Extract:
         * - MIC
         * - "EAPOL frame"
         */
    };

    return {
        "global_header": global_header,
        "frames": frames,
        "extract": extract
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
    if (big_endian == true || Wpa.use_big_endian) {
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

Wpa.dataToHex = function(data, start, end) {
    var result = [], hex;
    for (var i = start; i < end; i++) {
        hex = data.charCodeAt(i).toString(16);
        while (hex.length < 2) {
            hex = "0" + hex;
        }
        result.push(hex);
    }
    if (Wpa.use_big_endian) {
        result.reverse();
    }
    return result.join("");
};

/**
 * For debugging purposes only.
 * @return Debug string including the data length and pretty-printed hex values.
 */
Wpa.bytesToDebugText = function(data) {
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
    Wpa.use_big_endian = true;
    var magic_number = Wpa.dataToInt(data, 0, 4);
    if (magic_number === 3569595041) {
        Wpa.use_big_endian = false;
    } else {
        Wpa.use_big_endian = true;
    }
    return {
      "magic_number":  magic_number,
      "version_major": Wpa.dataToInt(data, 4, 6),
      "version_minor": Wpa.dataToInt(data, 6, 8),
      "thiszone":      Wpa.dataToInt(data, 8, 12, false, true),
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

    result.addr_destination = Wpa.dataToHex(data, 4, 10);
    result.addr_source      = Wpa.dataToHex(data, 10, 16);

    result.bssid = Wpa.dataToInt(data, 16, 22).toString(16);

    var frag_seq = Wpa.dataToInt(data, 22, 24);
    result.fragment_number = (frag_seq >>> 0) & 0b1111;
    result.sequence_number = (frag_seq >>> 4) & 0b111111111111;

    var frame_data;

    if (result.fc_version == 0
            && result.fc_type == 2 // Data Frame
            && result.fc_subtype == 8) {
        // QoS Data
        result.type = "EAPOLWpaKey";
        result.qos_control = Wpa.dataToInt(data, 24, 26).toString(2);
        frame_data = data.substring(26);
    }
    else {
        frame_data = data.substring(24);
    }

    // Parse remaining data in frame.
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
            && (result.fc_subtype == 0 || result.fc_subtype == 8)) {
        if (!result.fcf_protected) {
            result.type = "EAPOLWpaKey";
            result.data = Wpa.eapolWpaKey(frame_data);
        }
        else {
            // 802.11 data (tkip?)
        }

    } else {
        // Skip other frames.
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
        // TODO: Support other tag numbers.
        data = data.substring(2 + tag_length);
    }
    return result;
};

Wpa.AuthenticationFrame = function(data) {
    var reuslt = {};

    var fixed_params = data.substring(0, 6);

    result.auth_algorithm = Wpa.dataToInt(data, 0, 2);
    result.auth_seq       = Wpa.dataToInt(data, 2, 4);
    result.status_code    = Wpa.dataToInt(data, 4, 6);
    return result;
};

Wpa.eapolWpaKey = function(data) {
    //var logical_link_control = data.substring(0, 8);

    data = data.substring(8);
    var auth_version = Wpa.dataToInt(data, 0, 1);
    var auth_type = Wpa.dataToInt(data, 1, 2);

    var auth_length = Wpa.dataToInt(data, 2, 4, true, false);
    data = data.substring(4, 4 + auth_length);

    var key_descriptor = Wpa.dataToInt(data, 0, 1);
    var key_info = Wpa.dataToInt(data, 1, 3, true, false);
    var key_information = {
        "key_descriptor_version":    (key_info >>>  0) & 0b111,
        "key_type":                  (key_info >>>  3) & 0b1,
        "key_index":                 (key_info >>>  4) & 0b11,
        "install":                !!((key_info >>>  6) & 0b1 ),
        "ack":                    !!((key_info >>>  7) & 0b1 ),
        "mic":                    !!((key_info >>>  8) & 0b1 ),
        "secure":                 !!((key_info >>>  9) & 0b1 ),
        "error":                  !!((key_info >>> 10) & 0b1 ),
        "request":                !!((key_info >>> 11) & 0b1 ),
        "encrypted":              !!((key_info >>> 12) & 0b1 ),
        "smk":                    !!((key_info >>> 13) & 0b1 )
    };
    var key_length = Wpa.dataToInt(data, 3, 5, true, false);
    var replay_counter = Wpa.dataToInt(data, 5, 13, true, false);
    var key_nonce = Wpa.dataToHex(data, 13, 45);
    var key_iv = Wpa.dataToHex(data, 45, 61);
    var key_rsc = Wpa.dataToHex(data, 61, 69);
    var key_id = Wpa.dataToHex(data, 69, 77);
    var key_mic = Wpa.dataToHex(data, 77, 93);

    var key_data_length = Wpa.dataToInt(data, 93, 95, true, false);
    var key_data;
    if (key_data_length > 0) {
        key_data = Wpa.dataToHex(data, 95, 95 + key_data_length);
    }

    var result = {
        "auth_version": auth_version,
        "auth_type": auth_type,
        "auth_length": auth_length,
        "key_descriptor": key_descriptor,
        "key_information": key_information,
        "key_length": key_length,
        "replay_counter": replay_counter,
        "key_nonce": key_nonce,
        "key_iv": key_iv,
        "key_rsc": key_rsc,
        "key_id": key_id,
        "key_mic": key_mic,
    };
    if (key_data) {
        result.key_data_length = key_data_length;
        result.key_data = key_data;
    }
    return result;
};
