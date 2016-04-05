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


var CapFile = {};

function Wpa(bytes) {
    this.data_ = bytes;
    this.parse();
}

Wpa.use_big_endian = true;


/**
 * "Constructor" that parses the given data into packets and frames.
 * @param data (string) The data as a string (with charCodes);
 */
Wpa.prototype.parse = function() {
    this.global_header = CapFile.GlobalHeader(this.data_);

    this.frames = [];

    var packet_start = 24;
    while (packet_start < this.data_.length) {
        var ph = new CapFile.PacketHeader(this.data_.substring(packet_start, packet_start + 16));

        packet_start += 16;
        var pf = new CapFile.PacketFrame(this.data_.substring(packet_start, packet_start + ph.incl_len));
        if (pf.dot1x_data) {
            this.frames.push(pf);
        }

        packet_start += ph.incl_len;
    }
};

/*
 * Extract data from handshakes required for cracking.
 */
Wpa.prototype.extract_ = function() {
    var ssid, snonce, anonce, replay_counter, mic, frame_bytes;
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

/**
 * Converts subsection of 'data' into an integer.
 * @param data       (string) The data as a string (with charCodes).
 * @param start      (int)    The starting index of the subsection.
 * @param end        (int)    The ending index of the subsection.
 * @param big_endian (bool)   If data is in big-endian format, default: Wpa.use_big_endian
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
 */
CapFile.GlobalHeader = function(data) {
    this.data_ = data.substring(0, 24);
    Wpa.use_big_endian = true;
    this.magic_number = Wpa.dataToInt(this.data_, 0, 4);
    if (this.magic_number === 3569595041) {
        Wpa.use_big_endian = false;
    } else {
        Wpa.use_big_endian = true;
    }

    this.version_major = Wpa.dataToInt(this.data_, 4, 6);
    this.version_minor = Wpa.dataToInt(this.data_, 6, 8);
    this.thiszone = Wpa.dataToInt(this.data_, 8, 12, false, true);
    this.sigfigs = Wpa.dataToInt(this.data_, 12,16);
    this.snaplen = Wpa.dataToInt(this.data_, 16,20);
    this.network = Wpa.dataToInt(this.data_, 20,24);

    this.data_ = Wpa.dataToHex(this.data_, 0, this.data_.length);

    return this;
};

/**
 * Header for a single packet.
 * Contains vital "incl_len" which is the length of the packet data.
 */
CapFile.PacketHeader = function(data) {
    this.ts_sec = Wpa.dataToInt(data, 0, 4);
    this.ts_usec = Wpa.dataToInt(data, 4, 8);
    this.incl_len = Wpa.dataToInt(data, 8,12);
    this.orig_len = Wpa.dataToInt(data,12,16);
    return this;
};

/**
 * Packet frame information.
 * If frame is identified, will contain a "type" (string) representing the frame.
 */
CapFile.PacketFrame = function(data) {
    // Frame Control
    var fc = Wpa.dataToInt(data, 0, 1);

    this.frame_control = {};
    this.frame_control.version = (fc >>> 0) & 0b11;
    this.frame_control.type    = (fc >>> 2) & 0b11;
    this.frame_control.subtype = (fc >>> 4);

    // FrameControl Flags
    var fcf = Wpa.dataToInt(data, 1, 2);
    this.frame_control.flags = {};
    this.frame_control.flags.toDS          = !!(fcf >>> 0 & 0b1);
    this.frame_control.flags.fromDS        = !!(fcf >>> 1 & 0b1);
    this.frame_control.flags.moreFragments = !!(fcf >>> 2 & 0b1);
    this.frame_control.flags.retry         = !!(fcf >>> 3 & 0b1);
    this.frame_control.flags.pwrMgt        = !!(fcf >>> 4 & 0b1);
    this.frame_control.flags.moreData      = !!(fcf >>> 5 & 0b1);
    this.frame_control.flags.is_protected  = !!(fcf >>> 6 & 0b1);
    this.frame_control.flags.order         = !!(fcf >>> 7 & 0b1);

    this.duration = Wpa.dataToInt(data, 2, 4);

    this.addr_destination = Wpa.dataToHex(data, 4, 10);
    this.addr_source      = Wpa.dataToHex(data, 10, 16);

    this.bssid = Wpa.dataToHex(data, 16, 22);

    var frag_seq = Wpa.dataToInt(data, 22, 24);
    this.fragment_number = (frag_seq >>> 0) & 0b1111;
    this.sequence_number = (frag_seq >>> 4) & 0b111111111111;

    var frame_data = data.substring(24);

    var frame_types_version = this.frame_control.version.toString() +
        "." + this.frame_control.type.toString() +
        "." + this.frame_control.subtype.toString();
    var frame_type = FrameTypes[frame_types_version];
    if (frame_type) {
        this.type = frame_type.type;
        if (frame_type.builder) {
           if (frame_types_version == "0.2.0" && this.frame_control.flags.is_protected) {
               // Data varies if protected flag is set.
               this.type = "EAPOLWpaKeyData";
               this.tkip_init_vector = Wpa.dataToInt(frame_data, 0, 8).toString(16);
               this.tkip_key_index = Wpa.dataToInt(frame_data, 3, 4) & 0b1111;
               this.dot1x_data = Wpa.dataToHex(frame_data, 8, frame_data.length);
           } else {
                this.dot1x_data = new frame_type.builder(frame_data);
           }
        }
        else {
            this.dot1x_data = null;
        }
    }
    /*
    // Parse remaining data in frame based on frame control type.
    if        (this.frame_control.version == 0
            && this.frame_control.type == 0
            && this.frame_control.subtype == 8) {
        this.type = "BeaconResponse";
        this.dot1x_data = CapFile.BeaconFrame(frame_data);

    } else if (this.frame_control.version == 0
            && this.frame_control.type == 0
            && this.frame_control.subtype == 5) {
        this.type = "ProbeResponse";
        this.dot1x_data = CapFile.BeaconFrame(frame_data);

    } else if (this.frame_control.version == 0
            && this.frame_control.type == 0
            && this.frame_control.subtype == 4) {
        this.type = "ProbeRequest";

    } else if (this.frame_control.version == 0
            && this.frame_control.type == 0
            && this.frame_control.subtype == 11) {
        this.type = "Authentication";
        this.dot1x_data = CapFile.AuthenticationFrame(frame_data);

    } else if (this.frame_control.version == 0
            && this.frame_control.type == 0
            && this.frame_control.subtype == 0) {
        this.type = "AssociationRequest";

    } else if (this.frame_control.version == 0
            && this.frame_control.type == 0
            && this.frame_control.subtype == 1) {
        this.type = "AssociationResponse";

    } else if (this.frame_control.version == 0
            && this.frame_control.type == 2 // Data Frame
            && (this.frame_control.subtype == 0 || this.frame_control.subtype == 8)) {
        if (!this.frame_control.flags.is_protected) {

            if (this.frame_control.subtype == 8) {
                this.qos_control = Wpa.dataToInt(frame_data, 0, 2).toString(2);
                frame_data = data.substring(2);
            }

            this.type = "EAPOLWpaKey";
            this.dot1x_data = CapFile.EapolWpaKeyFrame(frame_data);
        }
        else {
            // 802.11 data (tkip?)
        }

    } else {
        // Skip other frames.
    }
    */

    return this;
};

CapFile.BeaconFrame = function(data) {
    var fixed_params = data.substring(0, 12);
    // TODO: Parse fixed params

    data = data.substring(12);
    this.tags = {};
    while (data.length > 0) {
        var tag = {};
        var tag_number = Wpa.dataToInt(data, 0, 1);

        var tag_length = Wpa.dataToInt(data, 1, 2);
        var tag_data = data.substring(2, 2 + tag_length);
        if (tag_number == 0) {
            // SSID
            tag.ssid = tag_data;
            this.tags[tag_number] = tag;
        }
        // TODO: Support other tag numbers.
        data = data.substring(2 + tag_length);
    }
    return this;
};

CapFile.AuthenticationFrame = function(data) {
    var fixed_params = data.substring(0, 6);

    this.auth_algorithm = Wpa.dataToInt(data, 0, 2);
    this.auth_seq       = Wpa.dataToInt(data, 2, 4);
    this.status_code    = Wpa.dataToInt(data, 4, 6);
    return this;
};

CapFile.EapolWpaKeyQosFrame = function(data) {
    var result = CapFile.EapolWpaKeyFrame(data.substring(2));
    result.qos_control = Wpa.dataToInt(data, 0, 2).toString(16);
    return result;
};

CapFile.EapolWpaKeyFrame = function(data) {
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


/** Types of understood packet frames. */
var FrameTypes = {
    "0.0.8": {
        "type": "BeaconResponse",
        "builder": CapFile.BeaconFrame
    },

    "0.0.4": {
        "type": "ProbeRequest",
    },
    "0.0.5": {
        "type": "ProbeResponse",
        "builder": CapFile.BeaconFrame
    },
    "0.0.11": {
        "type": "Authentication",
        "builder": CapFile.AuthenticationFrame
    },
    "0.0.0": {
        "type": "AssociationRequest",
    },
    "0.0.1": {
        "type": "AssociationResponse",
    },
    "0.2.0": {
        "type": "EAPOLWpaKey",
        "builder": CapFile.EapolWpaKeyFrame,
    },
    "0.2.8": {
        type: "EAPOLWpaKey",
        "builder": CapFile.EapolWpaKeyQosFrame,
    }
};
