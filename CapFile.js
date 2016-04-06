/*
 * Using string-as-bytes per https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/Sending_and_Receiving_Binary_Data
 */

/**
 * Parse the given bytes of a Packet Capture (PCAP) file.
 * Loads result into this.globalHeader and this.packetFrames.
 * TODO: Support 'debug' as a *callback*, sends debug text. e.g.
 *       var cf = CapFile(bytes, function(txt) { div.text = txt });
 */
function CapFile(bytes, debug) {
    CapFile.debug = debug || false;

    this.bytes_ = bytes;
    this.byteOffset_ = 0;

    this.parse();
};

// Configurations
CapFile.useBigEndian = true;

// Constants
CapFile.MAGIC_NUMBER_LITTLE_ENDIAN = 3569595041;
CapFile.SUPPORTED_PCAP_VERSION = "2.4";
CapFile.WLAN_HEADER_TYPE = 105;
CapFile.GLOBAL_HEADER_LENGTH = 24;
CapFile.PACKET_HEADER_LENGTH = 16;

/**
 * TODO: Log parse time for debug mode.
 */
CapFile.prototype.parse = function() {
    // First chunk of bytes is global header.
    this.globalHeader = CapFile.GlobalHeader.call(this);
    console.log(this.globalHeader.rawBytes_);

    // Ensure we can parse this data.
    if (this.globalHeader.version !== CapFile.SUPPORTED_PCAP_VERSION) {
        throw Error("Unsupported PCap File version (" + this.globalHeader.version + "). " +
                "Unable to parse.");
    }

    // Restrict parsing to WLAN types.
    if (this.globalHeader.headerType !== CapFile.WLAN_HEADER_TYPE) {
        throw Error("Unsupported (non-WLAN) Pcap file header type (" + this.globalHeader.headerType + "). " +
                "Unable to parse.");
    }

    // List of all identified frames in the cap file.
    this.packetFrames = [];

    var frame;

    this.byteOffset_ += CapFile.GLOBAL_HEADER_LENGTH;
    while (this.byteOffset_ < this.bytes_.length) {
        frame = CapFile.WlanFrame.call(this);

        this.packetFrames.push(frame);
    }
};

CapFile.prototype.getInt = function(startIndex, endIndex, useBigEndian, signed) {
    startIndex += this.byteOffset_;
    endIndex += this.byteOffset_;

    var result = 0, i, x;
    if (useBigEndian == true || CapFile.useBigEndian) {
        for (i = startIndex; i < endIndex; i++) {
            result = result << 8;
            x = this.bytes_.charCodeAt(i);
            result = result | x;
        }
    } else {
        for (i = endIndex - 1; i >= startIndex; i--) {
            result = result << 8;
            x = this.bytes_.charCodeAt(i);
            result = result | x;
        }
    }

    if (!signed) {
        // convert to unsigned.
        // See http://stackoverflow.com/a/1908655
        result = (result >>> 0);
    }
    return result;
};

CapFile.prototype.getHex = function(startIndex, endIndex, byteSpacer, colSpacer, rowSpacer) {
    startIndex += this.byteOffset_;
    endIndex += this.byteOffset_;

    var result = [], hex, i;
    if (byteSpacer) {
        result.push("");
    }
    for (i = startIndex; i < endIndex; i++) {
        hex = this.bytes_.charCodeAt(i).toString(16);
        while (hex.length < 2) {
            hex = "0" + hex;
        }
        if (rowSpacer && (i + 1) % 16 == 0) {
            hex += rowSpacer;
        } else if (colSpacer && (i + 1) % 8 == 0) {
            hex += colSpacer;
        }
        result.push(hex);
    }
    if (CapFile.useBigEndian) {
        result.reverse();
    }
    return result.join(byteSpacer || "");
};

/**
 * Details on https://wiki.wireshark.org/Development/LibpcapFileFormat
 */
CapFile.GlobalHeader = function() {
    // Presume big endian.
    CapFile.useBigEndian = true;

    // Set global endianess based on the magic number.
    var magic_number = this.getInt(0, 4);
    if (magic_number === CapFile.MAGIC_NUMBER_LITTLE_ENDIAN) {
        if (CapFile.debug) {
            console.log("[CapFile.js, Debug] Using Little-Endian byte-encoding due to magic number: " + magic_number);
        }
        CapFile.useBigEndian = false;
    } else {
        if (CapFile.debug) {
            console.log("[CapFile.js, Debug] Using Big-Endian byte-encoding due to magic number: " + magic_number);
        }
        CapFile.useBigEndian = true;
    }

    var result = {

        // Version of cap file.
        version: this.getInt(4, 6).toString(10) + "." + this.getInt(6, 8).toString(10),

        // Difference between capfile timestamps and GMT (in seconds)
        gmtOffset: this.getInt(8, 12, false, true),

        // The accuracy of the capfile timestamps
        sigFigs: this.getInt(12, 16),

        // Length of snapshot for the capture.
        // May cause "length" in PacketHeader to differ from "originalLength"
        snapshotLength: this.getInt(16, 20),

        // Link-layer header type. See http://www.tcpdump.org/linktypes.html
        // e.g. LINKTYPE_IEEE802_11 = 105 (for Wireless LAN)
        headerType: this.getInt(20, 24),

    };

    if (CapFile.debug) {
        console.log("[CapFile.js, Debug] GlobalHeader (24 bytes):\n" + this.getHex(0, 24, " ", "  ", "\n"));
    }

    return result;
};

CapFile.WlanFrame = function() {
    var result = {};

    // Parse header
    // Details on https://wiki.wireshark.org/Development/LibpcapFileFormat
    result.header = {
        timestampSec: this.getInt(0, 4),
        timestampMicrosec: this.getInt(4, 8),
        length: this.getInt(8, 12),
        originalLength: this.getInt(12, 16),
    };

    // Shift to frame body.
    this.byteOffset_ += CapFile.PACKET_HEADER_LENGTH;

    // Parse fields that are present in all Wlan frames.
    // Details on https://en.wikipedia.org/wiki/IEEE_802.11#Layer_2_.E2.80.93_Datagrams
    var frameControlBits = this.getInt(0, 1);
    result.frameControl = {
        version:  (frameControlBits >>> 0) & 0b11,
        type:     (frameControlBits >>> 2) & 0b11,
        subtype:  (frameControlBits >>> 4) & 0b1111,
    };

    var frameControlFlags = this.getInt(1, 2);
    result.frameControl.flags = {
        toDS:          !!(frameControlFlags >>> 0 & 0b1),
        fromDS:        !!(frameControlFlags >>> 1 & 0b1),
        moreFragments: !!(frameControlFlags >>> 2 & 0b1),
        retry:         !!(frameControlFlags >>> 3 & 0b1),
        powerMgt:      !!(frameControlFlags >>> 4 & 0b1),
        moreData:      !!(frameControlFlags >>> 5 & 0b1),
        is_protected:  !!(frameControlFlags >>> 6 & 0b1),
        order:         !!(frameControlFlags >>> 7 & 0b1),
    };

    result.duration = this.getInt(2, 4);

    result.addr1 = this.getHex(4, 10);

    // Parse body based on type/subtype
    var typeSubtype = result.frameControl.type + "." + result.frameControl.subtype;
    if (CapFile.FrameTypes.hasOwnProperty(typeSubtype)) {
        // We support this subtype
        console.log("OY", CapFile.FrameTypes[typeSubtype]);
        CapFile.FrameTypes[typeSubtype].builder.call(this, result);
    }

    // Shift to end of frame
    this.byteOffset_ += result.header.originalLength;

    return result;
};


CapFile.WlanFrame_Beacon = function(result) {
    
};

CapFile.FrameTypes = {
    /*
    "0.0": {
        name: "AssociationRequest",
    },
    "0.1": {
        name: "AssociationResponse",
    },
    */
    "0.8": {
        name: "Beacon",
        builder: CapFile.WlanFrame_Beacon
    },
};
