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
    this.bytesTotal = this.bytes_.length;
    this.bytesHex = this.getHex(0, this.bytesTotal, " ");

    this.parse();

    delete this.bytes_;
    delete this.byteOffset_;
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

    var intResult = 0, i, x;
    if (useBigEndian == true || CapFile.useBigEndian) {
        for (i = startIndex; i < endIndex; i++) {
            intResult = intResult << 8;
            x = this.bytes_.charCodeAt(i);
            intResult = intResult | x;
        }
    } else {
        for (i = endIndex - 1; i >= startIndex; i--) {
            intResult = intResult << 8;
            x = this.bytes_.charCodeAt(i);
            intResult = intResult | x;
        }
    }

    if (!signed) {
        // convert to unsigned.
        // See http://stackoverflow.com/a/1908655
        intResult = (intResult >>> 0);
    }
    return intResult;
};

CapFile.prototype.getHex = function(startIndex, endIndex, byteSpacer, colSpacer, rowSpacer) {
    startIndex += this.byteOffset_;
    endIndex += this.byteOffset_;

    var byteList = [], hex, i;
    if (byteSpacer) {
        byteList.push("");
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
        byteList.push(hex);
    }
    if (CapFile.useBigEndian) {
        byteList.reverse();
    }
    return byteList.join(byteSpacer || "");
};

CapFile.prototype.getBytes = function(startIndex, endIndex) {
    startIndex += this.byteOffset_;
    endIndex += this.byteOffset_;

    var byteList = [], hex, i;
    for (i = startIndex; i < endIndex; i++) {
        hex = this.bytes_.charAt(i);
        byteList.push(hex);
    }
    if (CapFile.useBigEndian) {
        byteList.reverse();
    }
    return byteList.join("");
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

    var headers = {

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

    return headers;
};

CapFile.WlanFrame = function() {
    var frame = {};

    // Parse header
    // Details on https://wiki.wireshark.org/Development/LibpcapFileFormat
    frame.header = {
        timestampSec: this.getInt(0, 4),
        timestampMicrosec: this.getInt(4, 8),
        length: this.getInt(8, 12),
        originalLength: this.getInt(12, 16),
    };

    // Convert timestamps to date.
    var ts_usec = frame.header.timestampSec * 1000;
    ts_usec += (frame.header.timestampMicrosec / 1000);
    ts_usec += this.globalHeader.gmtOffset;
    frame.header.timestamp = new Date(ts_usec);

    // Shift to frame body.
    this.byteOffset_ += CapFile.PACKET_HEADER_LENGTH;

    // Mark where this packet ends.
    var endOfPacketOffset = this.byteOffset_ + frame.header.originalLength;

    // Parse fields that are present in all Wlan frames.
    // Details on https://en.wikipedia.org/wiki/IEEE_802.11#Layer_2_.E2.80.93_Datagrams
    var frameControlBits = this.getInt(0, 1);
    frame.frameControl = {
        version:  (frameControlBits >>> 0) & 0b11,
        type:     (frameControlBits >>> 2) & 0b11,
        subtype:  (frameControlBits >>> 4) & 0b1111,
    };

    var frameControlFlags = this.getInt(1, 2);
    frame.frameControl.flags = {
        toDS:          !!(frameControlFlags >>> 0 & 0b1),
        fromDS:        !!(frameControlFlags >>> 1 & 0b1),
        moreFragments: !!(frameControlFlags >>> 2 & 0b1),
        retry:         !!(frameControlFlags >>> 3 & 0b1),
        powerMgt:      !!(frameControlFlags >>> 4 & 0b1),
        moreData:      !!(frameControlFlags >>> 5 & 0b1),
        is_protected:  !!(frameControlFlags >>> 6 & 0b1),
        order:         !!(frameControlFlags >>> 7 & 0b1),
    };

    frame.duration = this.getInt(2, 4);

    frame.addr1 = this.getHex(4, 10);

    // From here on, the fields may vary depending on the Frame Type (MANAGEMENT, CONTROL, DATA).
    if (frame.frameControl.type === CapFile.WlanFrame.Types.MANAGEMENT) {
        // Non-802.11 parameters are easy.
        frame.addr2 = this.getHex(10, 16);
        frame.addr3 = this.getHex(16, 22);
        var frag_seq = this.getInt(22, 24);
        frame.fragment_number = (frag_seq >>> 0) & 0b1111;
        frame.sequence_number = (frag_seq >>> 4) & 0b111111111111;

        // Skip to 802.1x frame
        this.byteOffset_ += 24;

        // Parse frame in context of a Control Frame.
        CapFile.WlanFrame.Control.call(this, frame, endOfPacketOffset);
    }
    else if (frame.frameControl.type === CapFile.WlanFrame.Types.CONTROL) {
        // No other data to parse.
    }
    else if (frame.frameControl.type === CapFile.WlanFrame.Types.DATA) {
        // Parse data depending on subtype.
    }

    // Shift to end of frame
    this.byteOffset_ = endOfPacketOffset;

    return frame;
};

CapFile.WlanFrame.Types = {
    MANAGEMENT: 0,
    CONTROL: 1,
    DATA: 2
};

CapFile.WlanFrame.Control = function(frame, endOfPacketOffset) {
    // TODO: Parse fixed and (if they exist) tagged parameters.
    //       Fixed params length varies depending on subtype.
    //       Beacon:12, Deauth:2, ProbeResponse:12, AssociationResponse:6,
    var fixedParamLength;
    if (frame.frameControl.subtype === 0) {
        frame.name = "AssociationRequest";
        fixedParamLength = 4;
    }
    else if (frame.frameControl.subtype === 1) {
        frame.name = "AssociationResponse";
        fixedParamLength = 6;
    }
    else if (frame.frameControl.subtype === 8) {
        frame.name = "Beacon";
        fixedParamLength = 12;
    }
    else if (frame.frameControl.subtype === 5) {
        frame.name = "ProbeResponse";
        fixedParamLength = 12;
    }
    else if (frame.frameControl.subtype === 11) {
        frame.name = "Authentication";
        fixedParamLength = 6;
    }
    else if (frame.frameControl.subtype === 12) {
        frame.name = "Deauthentication";
        fixedParamLength = 2;
    }
    else if (frame.frameControl.subtype === 13) {
        frame.name = "Action";
        fixedParamLength = 9;
    }

    console.log("Fixed param length: " + fixedParamLength);
    if (!fixedParamLength) {
        frame.name = "Unknown";
        // Unable to parse tagged parameters without knowing fixed parameter length.
        return;
    }

    // TODO: Parse fixed parameters.

    this.byteOffset_ += fixedParamLength;

    frame.taggedParameters = {};

    // Parse tagged parameters.
    while (this.byteOffset_ < endOfPacketOffset) {
        var tag = {};
        var tagIndex = this.getInt(0, 1);
        var tagLength = this.getInt(1, 2);
        if (tagIndex === 0) {
            // SSID
            var tagData = this.getBytes(2, 2 + tagLength);
            frame.taggedParameters[tagIndex] = {
                name: "SSID",
                length: tagLength,
                data: tagData
            };
        }
        else {
            var tagData = this.getHex(2, 2 + tagLength);
            frame.taggedParameters[tagIndex] = {
                name: "Unknown",
                length: tagLength,
                data: tagData
            };
        }
        this.byteOffset_ += tagLength + 2;
    }
};

