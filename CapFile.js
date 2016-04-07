/*
 * DESIGN
 * Using string-as-bytes per https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/Sending_and_Receiving_Binary_Data
 */

/**
 * RESEARCH
 * Additional Reading and References:
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
 *
 * Load byte array from URL: https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/Sending_and_Receiving_Binary_Data
 *
 * aircrack-ng sample WPA file: http://www.aircrack-ng.org/doku.php?id=wpa_capture
 * Parsing .cap files: http://systemsarchitect.net/2014/03/12/parsing-binary-data-in-php-on-an-example-with-the-pcap-format/
 *
 * http://www.willhackforsushi.com/papers/80211_Pocket_Reference_Guide.pdf
 *
 * Details on 802.11 packet structures - http://www.studioreti.it/slide/802-11-Frame_E_C.pdf
 *
 *
 * TODO: 
 *  - Check bytes_.length >= header.length before parsing! (chocobo-new.cap is 'truncated', gives weird results)
 *  - Look at using ArrayBuffer + DataView internal JS structures.
 *  - Browser compatibility  (ie, chrome, safari)
 */


/**
 * Parse the given bytes of a Packet Capture (PCAP) file.
 * Loads result into boejct this.globalHeader (always) and list this.packetFrames (for known frame types).
 *
 * @param bytes - (string? bytes?) Raw bytes from a .cap Pcap file.
 * @param debug - (boolean) Flag to dump debug information to the console (default: false)
 *
 * TODO: Support 'debug' as a *callback*, sends debug text. e.g.
 *       var cf = CapFile(bytes, function(txt) { input.value += txt + "\n" });
 */
function CapFile(bytes, debug) {
    CapFile.debug = debug || false;

    this.bytes_ = bytes;
    this.byteOffset_ = 0;
    this.bytesTotal = this.bytes_.length;
    //this.bytesHex = this.getHex(0, this.bytesTotal, " ");

    this.parse();

    delete this.bytes_;
    delete this.byteOffset_;
};

// Configurations
CapFile.useBigEndian = true;

// Constants
CapFile.MAGIC_NUMBER_LITTLE_ENDIAN = "a1b2c3d4";
CapFile.SUPPORTED_PCAP_VERSION = "2.4";
CapFile.WLAN_HEADER_TYPE = 105;
CapFile.GLOBAL_HEADER_LENGTH = 24;
CapFile.PACKET_HEADER_LENGTH = 16;

/**
 * TODO: Log parse time for debug mode.
 */
CapFile.prototype.parse = function() {
    // First chunk of bytes is global header.
    this.byteOffset_ = 0;
    this.globalHeader = CapFile.GlobalHeader.call(this);

    // Ensure we can parse this Pcap file/ format version.
    if (this.globalHeader.version !== CapFile.SUPPORTED_PCAP_VERSION) {
        throw Error("Unsupported PCap File version (" + this.globalHeader.version + "). " +
                "Unable to parse.");
    }

    // Restrict parsing to WLAN types.
    if (this.globalHeader.headerType !== CapFile.WLAN_HEADER_TYPE) {
        throw Error("Unsupported (non-WLAN) Pcap file header type (" + this.globalHeader.headerType + "). " +
                "Unable to parse.");
    }

    // Skip past Blobal Header bytes.
    this.byteOffset_ += CapFile.GLOBAL_HEADER_LENGTH;

    // List of all identified frames in the cap file.
    this.packetFrames = [];

    var frame;
    while (this.byteOffset_ < this.bytes_.length) {
        frame = CapFile.WlanFrame.call(this);
        if (frame.name.indexOf("Unknown") === -1) {
            // Only add known packet types to frames list.
            this.packetFrames.push(frame);
        }
    }
};

/**
 * Extract integer from bytes_ at current byteOffset_
 *
 * @param startIndex   - Index of first byte (added to byteOffset_)
 * @param endIndex     - Index of last byte (added to byteOffset_)
 * @param useBigEndian - Override configuration, expect big-endian-style byte order (default: CapFile.useBigEndian)
 * @param signed       - If integer should be signed (default: false)
 *
 * @return (int) Numeric-representation of data at byte location.
 */
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

/**
 * Extract hex characters from bytes_ at current byteOffset_
 *
 * @param startIndex - (int) Index of first byte (added to byteOffset_)
 * @param endIndex   - (int) Index of last byte (added to byteOffset_)
 * @param byteSpacer - (string) Separator between bytes (default: empty string)
 * @param colSpacer  - (string) Separator between chunks of 8 bytes (default: empty string)
 * @param rowSpacer  - (string) Separator between chunks of 16 bytes (default: empty string)
 *
 * @return (string) Hex-representation of data at byte location.
 */
CapFile.prototype.getHex = function(startIndex, endIndex, byteSpacer, colSpacer, rowSpacer) {
    startIndex += this.byteOffset_;
    endIndex += this.byteOffset_;

    var byteList = [], hex, i, counter = 0;
    if (byteSpacer) {
        byteList.push("");
    }
    for (i = startIndex; i < endIndex; i++) {
        hex = this.bytes_.charCodeAt(i).toString(16);
        while (hex.length < 2) {
            hex = "0" + hex;
        }
        counter++;
        if (rowSpacer && counter % 16 == 0) {
            hex += rowSpacer;
        } else if (colSpacer && counter % 8 == 0) {
            hex += colSpacer;
        }
        byteList.push(hex);
    }
    if (CapFile.useBigEndian) {
        byteList.reverse();
    }
    return byteList.join(byteSpacer || "");
};

/**
 * Extract raw bytes from bytes_ at current byteOffset_
 *
 * @param startIndex - (int) Index of first byte (added to byteOffset_)
 * @param endIndex   - (int) Index of last byte (added to byteOffset_)
 *
 * @return (string? bytes?) Raw bytes of data at byte location.
 */
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
 * Parses Pcap file global header (starting at byteOffset_, presumably "0").
 *
 * Requires reference to "this" CapFile object.
 *
 * More info on https://wiki.wireshark.org/Development/LibpcapFileFormat
 *
 * @return (object) containing:
 *     version        - (string) in format <major>.<minor> e.g. 2.4
 *     gmtOffset      - (signed int) Offset between packet timestamps and GMT timezone
 *     sigFigs        - (int) Accuracy of timestamps
 *     snapshotLength - (int) Length of snapshot for the capture (in bytes)
 *     headerType     - (int) Link-Layer header type, e.g. LINKTYPE_IEEE802.11 = 105 (Wireless LAN)
 */
CapFile.GlobalHeader = function() {
    // Presume big endian.
    CapFile.useBigEndian = true;

    // Set global endianess based on the magic number.
    var magic_number = this.getHex(0, 4);
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
        headerType: this.getInt(20, 24)

    };

    if (CapFile.debug) {
        console.log("[CapFile.js, Debug] GlobalHeader (24 bytes):\n" + this.getHex(0, 24, " ", "  ", "\n"));
    }

    return headers;
};

/**
 * "Frame Builder". Parses entire frame at current bytesOffset_ location.
 * Only supports detailed parsing of certain 802.11 WLAN frames - see CapFile.WlanFrame.* for more info
 *
 * Requires reference to "this" CapFile object -- call using CapFile.WlanFrame.call(this);
 *
 * @return (object) Frame information containing: {
 *      header: {
 *          timestamp: (Date) Timestamp of the packet as a Date object
 *          length:    (int)  Length of the packet/frame (in bytes)
 *      },
 *      frameControl: {
 *          version: (int) Frame version
 *          type:    (int) Frame type (0=Management, 1=Control, 2=Data)
 *          subtype: (int) Frame subtype
 *          flags: {
 *              toDS:         (boolean)
 *              fromDS:       (boolean)
 *              moreFragments:(boolean)
 *              retry:        (boolean)
 *              powerMgt:     (boolean)
 *              moreData:     (boolean)
 *              is_protected: (boolean)
 *              order:        (boolean)
 *          }
 *      },
 *      duration: (int)
 *      addr1:    (string) First address, as hex characters (no separator).
 *  }
 *
 *  CONTROL FRAMES (type:1) will not contain any additional information.
 *
 *  MANAGEMENT FRAMES (type:0) and DATA FRAMES (type:2) both contain more information: {
 *      addr2: (string) Second address, as hex characters (no separator).
 *      addr3: (string) Second address, as hex characters (no separator).
 *      fragmentNumber: (int)
 *      sequenceNumber: (int)
 *  }
 *
 * More info on MANAGEMENT frames: see CapFile.WlanFrame.Management
 * More info on DATA frames:       see CapFile.WlanFrame.Data
 *
 */
CapFile.WlanFrame = function() {
    var frame = {};

    // Parse header
    // Details on https://wiki.wireshark.org/Development/LibpcapFileFormat

    // Convert timestamp to Date.
    var timestampSec = this.getInt(0, 4);
    var timestampUsec = this.getInt(4, 8);
    var ts_usec = timestampSec * 1000;
    ts_usec += (timestampUsec / 1000);
    ts_usec += this.globalHeader.gmtOffset;
    frame.header = {
        timestamp: new Date(ts_usec),
        length: this.getInt(8, 12),
        originalLength: this.getInt(12, 16)
    };

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
        subtype:  (frameControlBits >>> 4) & 0b1111
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
        order:         !!(frameControlFlags >>> 7 & 0b1)
    };

    frame.duration = this.getInt(2, 4);

    frame.addr1 = this.getHex(4, 10);

    // From here on, the fields may vary depending on the Frame Type (MANAGEMENT, CONTROL, DATA).
    if (frame.frameControl.type === CapFile.WlanFrame.Types.CONTROL) {
        // No other relevant data to parse.
    } else {
        // Capture similarities between Management and Data frames.
        frame.addr2 = this.getHex(10, 16);
        frame.addr3 = this.getHex(16, 22);
        var fragSeq = this.getInt(22, 24);
        frame.fragmentNumber = (fragSeq >>> 0) & 0b1111;
        frame.sequenceNumber = (fragSeq >>> 4) & 0b111111111111;

        // Skip to just past the sequence number.
        this.byteOffset_ += 24;

        if (frame.frameControl.type === CapFile.WlanFrame.Types.MANAGEMENT) {
            // Parse frame in context of a Management Frame.
            CapFile.WlanFrame.Management.call(this, frame, endOfPacketOffset);
        }
        else if (frame.frameControl.type === CapFile.WlanFrame.Types.DATA) {
            // Parse frame in context of a Data frame.
            CapFile.WlanFrame.Data.call(this, frame, endOfPacketOffset);
        }
    }

    // Shift to end of frame.
    this.byteOffset_ = endOfPacketOffset;

    return frame;
};

CapFile.WlanFrame.Types = {
    MANAGEMENT: 0,
    CONTROL: 1,
    DATA: 2
};

/**
 * Adds any additional information about this Management packet.
 * Only a subset of Management frames are supported.
 *
 * Focus is on getting SSID from the Management frames' "tagged parameters".
 * Other tagged parameters are read (and stored as Hex) but are not parsed.
 *
 * Requires reference to "this" CapFile object -- call using CapFile.WlanFrame.Management.call(this, ...);
 *
 * Increments CapFile.byteOffset_ to end of the Management frame.
 *
 * @param frame - (object) Reference to the currently-parsed frame.
 * @param endOfPacketOffset - (int) The Offset, in relation to byteOffset_, in which this packet ends.
 */
CapFile.WlanFrame.Management = function(frame, endOfPacketOffset) {
    // Management frames contain:
    // 1. Fixed Parameters (variable length, depends on frameControl.subtype).
    // 2. Tagged Parameters (variable length, defined in 'length' bytes).

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

    if (!fixedParamLength) {
        // Unable to parse tagged parameters without knowing fixed parameter length.
        frame.name = "Unknown Management Frame subtype (" + frame.frameControl.subtype + ")";
        return;
    }

    // TODO: Parse fixed parameters. Skipping for now.
    this.byteOffset_ += fixedParamLength;


    // Parse tagged parameters.
    frame.taggedParameters = {};
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
            // Don't care about other tags.
            var tagData = this.getHex(2, 2 + tagLength);
            frame.taggedParameters[tagIndex] = {
                name: "N/A",
                length: tagLength,
                data: tagData
            };
        }
        // Shift to next tagged paramter (or end of packet).
        this.byteOffset_ += tagLength + 2;
    }
};

/**
 * Adds any additional information about this Data frame.
 * Only a small subset of Data frames are supported.
 *
 * Focus is on getting EAPOL (WPA handshake-related) information.
 *
 * Requires reference to "this" CapFile object -- call using CapFile.WlanFrame.Data.call(this, ...);
 *
 * Increments CapFile.byteOffset_ to end of the Data frame (if known).
 * Otherwise does not change CapFile.byteOffset_
 *
 * @param frame - (object) Reference to the currently-parsed frame.
 * @param endOfPacketOffset - (int) The Offset, in relation to byteOffset_, in which this packet ends.
 */
CapFile.WlanFrame.Data = function(frame, endOfPacketOffset) {
    if ((frame.frameControl.subtype & 0b111) !== 0) {
        // Only support EAPOL (and EAPOL+QoS) packets.
        frame.name = "Unknown Data Frame subtype (" + frame.frameControl.subtype + ")";
        return;
    }
    if (frame.frameControl.flags.toDS && frame.frameControl.flags.fromDS) {
        // toDS and fromDS are set, expect addr4
        frame.addr4 = this.getHex(0, 6);
        this.byteOffset_ += 6;
    }
    if ((frame.frameControl.subtype & 0b1000) === 8) {
        // QoS flag is set. Expect QoS control field.
        frame.qosControl = this.getHex(0, 2);
        this.byteOffset_ += 2;
        frame.name = "EAPOL (QoS)";
    }
    else {
        frame.name = "EAPOL";
    }
    if (frame.frameControl.flags.order) {
        // Expect (and skip) HT Control field.
        this.byteOffset_ += 4;
    }

    // Skip Logical-Link Control bytes
    this.byteOffset_ += 8;

    // Parse Data frame body -- expect 802.1x auth packet.
    var authVersion = this.getInt(0, 1);
    var authType = this.getInt(1, 2);
    frame.auth = {
        version:            authVersion, // 1=802.1X-2001
        type:               authType, // 3=Key
        authLength:         this.getInt(2, 4, true, false),
        keyDescriptorType:  this.getInt(4, 5), // 2=EAPOL RSN Key
        keyInfo:            this.getInt(5, 7, true, false),
        keyLength:          this.getInt(7, 9, true, false),
        replayCounter:      this.getInt(9, 17, true, false),
        keyNonce:           this.getHex(17, 49),
        keyIV:              this.getHex(49, 65),
        keyRSC:             this.getHex(65, 73),
        keyID:              this.getHex(73, 81),
        keyMIC:             this.getHex(81, 97),
        keyDataLength:      this.getInt(97, 99, true, false)
    };
    frame.auth.keyInfoFlags = {
        keyDescriptorVersion:      (frame.auth.keyInfo >>>  0) & 0b111, // 2=AES Cipher, HMAC-SHA1 MIC
        keyType:                   (frame.auth.keyInfo >>>  3) & 0b1,   // 1=Pairwise Key
        keyIndex:                  (frame.auth.keyInfo >>>  4) & 0b11,
        install:                !!((frame.auth.keyInfo >>>  6) & 0b1 ),
        ack:                    !!((frame.auth.keyInfo >>>  7) & 0b1 ),
        mic:                    !!((frame.auth.keyInfo >>>  8) & 0b1 ),
        secure:                 !!((frame.auth.keyInfo >>>  9) & 0b1 ),
        error:                  !!((frame.auth.keyInfo >>> 10) & 0b1 ),
        request:                !!((frame.auth.keyInfo >>> 11) & 0b1 ),
        encrypted:              !!((frame.auth.keyInfo >>> 12) & 0b1 )
    };
    this.byteOffset_ += 99;

    if (frame.auth.keyDataLength > 0) {
        frame.auth.keyData = this.getHex(0, frame.auth.keyDataLength);
        this.byteOffset_ += frame.auth.keyDataLength;
    }

};

/**
 * TODO: Identify 4-way handshake(s), extract information required for calculating PMK.
 */
CapFile.prototype.extractPmkFields = function() {
    var ssid, snonce, anonce, replay_counter, mic, frame_bytes;
    // Look for SSID name in previous beacons/auth packets

    // Look for last 3 frames of handshake

    /* Handshake (2 of 4):
     * mic:true
     * ack:false
     * install:false
     * keyDataLength > 0)
     * 
     * Extract:
     * - keynonce (SNonce , the nonce from STATION)
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

