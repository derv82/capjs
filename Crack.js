/**
 * Enables cracking of handshake information (See CapFile.extractPmKFields).
 *
 * Uses Crypto-JS for HMAC-SHA1 and PBKDF2: https://github.com/brix/crypto-js
 *
 * References / Knowledge Sharing:
 *
 * http://security.stackexchange.com/questions/66008/how-exactly-does-4-way-handshake-cracking-work
 * - Explains how to Handshake data relates to PMK, PTK, KCK, MIC.
 *
 * https://hashcat.net/forum/thread-1745-post-9937.html#pid9937
 * - Extremely-detailed info on calculating PMK, PTK, and KCK.
 *
 * https://github.com/roobixx/cowpatty/blob/master/cowpatty.c
 * - Implementation of WPA handshake cracking in C.
 * - Specificaly https://github.com/roobixx/cowpatty/blob/master/cowpatty.c#L274
 *
 * http://stackoverflow.com/questions/18298387/pbkdf2-result-is-different-in-cryptojs-and-ios
 * - Explains that inputs to CryptoJS must be CryptoJS-encoded binary objects (with 'words' and 'sigDigits').
 *
 * http://stackoverflow.com/questions/12018920/wpa-handshake-with-python-hashing-difficulties
 * - Python-implementation of handshake cracking.
 * - Notes that the inputs to the PRF should be *bytes*, not ascii hex characters.
 *
 * http://sid.rstack.org/pres/0810_BACon_WPA2_en.pdf
 * - More reading on weaknesses in WPA, possible ways to speed up cracking, etc.
 *
 * https://pyrit.wordpress.com/2011/04/16/known-plaintext-attack-against-ccmp/
 * - Possible 'speedier way' to crack CCMP based on first 6 bytes of result.
 * - Found at http://security.stackexchange.com/a/6617
 */

/**
 * Algorithm:
 *
 * Construct PMK using
 *  - passphrase (from user input or list) and
 *  - SSID (from user input or beacon frame).
 * pmk = pbkdf2_sha1(passphrase, ssid, 4096, 256)
 *
 * Construct PTK using
 *  - PMK (step 1)
 *  - AP bssid, STATION bssid, ANonce, SNonce (from Handshake 3 of 4)
 * ... (wpa_pmk_to_ptk)
 *
 * Construct MIC we expect to see in 4-of-4 using
 *  - PTK (Step 2)
 *  - EAPOL Frame (Handshake 4 of 4)
 */

/**
 * Initializes WPA cracker instance.
 * @param handshake (object) Data from 4-way handshake (see CapFile.extractPmkFields)
 * @param debug (boolean or function) If 'true': Dumps debug information to console.
 *                                    If 'false': Does not dump anything to console.
 *                                    If given a function, calls function with debug text.
 */
function Crack(handshake, debug) {
    if (debug) {
        if (typeof debug === "boolean") {
            // Default debug function
            Crack.debug = function(txt) {
                console.log("[Crack.js] " + txt);
            }
        }
        else if (typeof debug === "function") {
            Crack.debug = debug;
        }
        else {
            throw Error("Unexpected type of 'debug' option: " + (typeof debug));
        }
    }
    this.pbkdf2ConfigForPmk = {
        keySize: 64/8,
        iterations: 4096
    };
    this.handshake = handshake;
    this.prfPrefix = this.getPrfPrefix();
}

/**
 * Convert given string to hexadecimal characters.
 * @param s (string) Text to convert to hex.
 * @return (string) Hexadecimal-representation of "s".
 */
Crack.stringToHex = function(s) {
    var result = "", i, x;
    for (i = 0; i < s.length; i++) {
        x = s.charCodeAt(i).toString(16);
        while (x.length < 2) {
            x = "0" + x;
        }
        result += x;
    }
    return result;
};

/**
 * Compute prefix of one of the inputs to Pseudo-Random Function (PRF, see Crack.kckFromPmk).
 * The "prefix" contains the "Pairwise Key Expansion", addresses, and nonces.
 * @return (string, hex) PRF prefix.
 */
Crack.prototype.getPrfPrefix = function() {
    var prefix = "";
    prefix = Crack.stringToHex("Pairwise key expansion");
    prefix += "00";
    if (this.handshake.srcAddress < this.handshake.dstAddress) {
        prefix += this.handshake.srcAddress;
        prefix += this.handshake.dstAddress;
    } else {
        prefix += this.handshake.dstAddress;
        prefix += this.handshake.srcAddress;
    }
    if (this.handshake.snonce < this.handshake.anonce) {
        prefix += this.handshake.snonce;
        prefix += this.handshake.anonce;
    } else {
        prefix += this.handshake.anonce;
        prefix += this.handshake.snonce;
    }
    return prefix;
};

/**
 * Calculates Pairwise Master Key (PMK).
 * Uses PBKDF2 which may take a while...
 *
 * @param key (string) The plaintext key/password (PSK).
 * @param ssid (string, optional) SSID (name of Wireless Access Point). Uses SSID from CapFile if not given.
 * @return (CryptoJS-encoded object) The PMK (256bits/32Bytes).
 */
Crack.prototype.pmk = function(key, ssid) {
    // Tribble
    //return CryptoJS.enc.Hex.parse("273c545d3be7e3fd4510fb5509486ba77f32c39716c4d63bf86de6b808387a77");

    // Netgear 2/158
    //return CryptoJS.enc.Hex.parse("01b809f9ab2fb5dc47984f52fb2d112e13d84ccb6b86d4a7193ec5299f851c48");

    if (Crack.debug) {
        Crack.debug("Constructing PMK using PDKDF2(psk:" + key + ", ssid:" + this.handshake.ssid + ")...");
    }

    var pmk = CryptoJS.PBKDF2(key, ssid || this.handshake.ssid, this.pbkdf2ConfigForPmk);

    if (Crack.debug) {
        Crack.debug("PMK (Pairwise Master Key): " + pmk.toString());
    }

    return pmk;
};


/**
 * Psudo-Random Function to calculate KCK (Key-Confirmation Key) from the PTK (Pairwise Transient Key).
 * Computes part of PTK using the given PMK.
 *
 * Uses "prfPrefix" calculated in Crack.getPrfPrefix().
 *
 * @param pmk (CryptoJS-encoded object) The PMK, calculated from Crack.pmk()
 * @return (string, hex) The KCK (first 16 bytes of the PTK).
 *
 */
Crack.prototype.kckFromPmk = function(pmk) {
    if (Crack.debug) {
        Crack.debug("Constructing KCK using handshake values, Hmac-SHA1, and the PMK...");
    }

    // Pseudo-Random function based on http://crypto.stackexchange.com/a/33192
    var i = 0, ptk = "", thisPrefix;
    while (i < (64 * 8 + 159) / 160) {
        // Append the current iteration counter as a (hex) byte to the prefix.
        thisPrefix = this.prfPrefix + ("0" + i);

        thisPrefix = CryptoJS.enc.Hex.parse(thisPrefix);
        ptk += CryptoJS.HmacSHA1(thisPrefix, pmk).toString();

        i++;
    }

    // Extract first 16 bytes (32 hex characters) of PTK to get KCK.
    var kck = ptk.substring(0, 32);

    if (Crack.debug) {
        Crack.debug("KCK (Key-Confirmation Key) : " + kck);
    }

    return kck;
};

/**
 * Calculate MIC using KCK (given) and EAPOL frame bytes (from a message in the 4-way handshake).
 *
 * @param kck (string, hex) The Key-ConfirmationKey (KCK) computed from Crack.kckFromPmk().
 * @return (string, hex) The expected MIC.
 */
Crack.prototype.micFromKck = function(kck) {
    kck = CryptoJS.enc.Hex.parse(kck);

    // NOTE: We expect the "MIC" portion of the EAPOL frame bytes to be *zeroed* out! From the 802.11 spec:
    // MIC(KCK, EAPOL) – MIC computed over the body of this EAPOL-Key frame with the Key MIC field first initialized to 0
    var bytes = CryptoJS.enc.Hex.parse(this.handshake.eapolFrameBytes);
    if (Crack.debug) {
        Crack.debug("EAPOL packet frame bytes: " + bytes.toString());
    }

    var computedMic;
    if (this.handshake.keyDescriptorVersion === 1) {
        if (Crack.debug) {
            Crack.debug("Using Hmac-MD5 for computing WPA MIC...");
        }
        computedMic = CryptoJS.HmacMD5(bytes, kck).toString();
    }
    else if (this.handshake.keyDescriptorVersion === 2) {
        if (Crack.debug) {
            Crack.debug("Using Hmac-SHA1 for computing WPA2 MIC");
        }
        computedMic = CryptoJS.HmacSHA1(bytes, kck).toString();

        // Extract 0-128 MSB per the 802.11 spec.
        computedMic = computedMic.substring(0, 32);
    }
    else {
        throw Error("Unknown key descriptor version: " + this.handshake.keyDescriptorVersion + ", expecting '1' or '2'");
    }

    if (Crack.debug) {
        Crack.debug("Computed Mic (based on PMK & KCK): " + computedMic);
        Crack.debug("Expected Mic (from Handshake packet): " + this.handshake.mic);
    }

    return computedMic;
}

Crack.prototype.tryPSK = function(psk) {
    var pmk = this.pmk(psk);
    var kck = this.kckFromPmk(pmk);
    var computedMic = this.micFromKck(kck);
    return (computedMic === this.handshake.mic);
};

/**
 * Asserts cracking method for WPA (TKIP) works.
 */
Crack.test_WPA1 = function(debug) {
    var handshake = {
        ssid: "Netgear 2/158",
        bssid: "001e2ae0bdd0",
        snonce: "60eff10088077f8b03a0e2fc2fc37e1fe1f30f9f7cfbcfb2826f26f3379c4318",
        anonce: "61c9a3f5cdcdf5fae5fd760836b8008c863aa2317022c7a202434554fb38452b",
        srcAddress: "001e2ae0bdd0",
        dstAddress: "cc08e0620bc8",
        mic: "45282522bc6707d6a70a0317a3ed48f0",
        keyLength: 32,
        keyDescriptorVersion: 1, // WPA
        eapolFrameBytes: "0103005ffe01090020000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        // PSK is 10zZz10ZZzZ
    };

    var c = new Crack(handshake, debug);

    // Assert PMK is accurate.
    var pmk = c.pmk("10zZz10ZZzZ");
    if (pmk.toString() !== "01b809f9ab2fb5dc47984f52fb2d112e13d84ccb6b86d4a7193ec5299f851c48") {
        throw Error("Expected PMK does not match. Got " + pmk.toString());
    }

    // Assert KCK is accurate.
    var kck = c.kckFromPmk(pmk);
    if (kck !== "bf49a95f0494f44427162f38696ef8b6") {
        throw Error("Expected KCK does not match. Got " + kck.toString());
    }

    var mic = c.micFromKck(kck);
    if (mic !== "45282522bc6707d6a70a0317a3ed48f0") {
        throw Error("Expected MIC does not match. Got " + mic);
    }
    Crack.debug("Crack.test_WPA1 passed.");
};

/**
 * Asserts cracking method for WPA2 (CCMP) works.
 */
Crack.test_WPA2 = function(debug) {
    var handshake = {
        ssid: "Tribble",
        bssid: "002275ecf9c9",
        snonce: "da12c942e9dfcbe67068438f87cd4ce49b253e3c7347bacc8f9aa4ab310e6e9f",
        anonce: "f5f5cd2ca691efe420224f466d3eb1633ef368ac93de64079ef4d9ca8129fa1b",
        srcAddress: "f4ce46629c64",
        dstAddress: "002275ecf9c9",
        replayCounter: 2925,
        keyLength: 16,
        mic: "646debf34b677fbfd78c5724dc9ea442",
        keyDescriptorVersion: 2, // WPA2
        eapolFrameBytes: "0103005f02030a00000000000000000b6dda12c942e9dfcbe67068438f87cd4ce49b253e3c7347bacc8f9aa4ab310e6e9f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        // PSK is dandelion
    };

    var c = new Crack(handshake, debug);

    // Assert PMK is accurate.
    var pmk = c.pmk("dandelion");
    if (pmk.toString() !== "273c545d3be7e3fd4510fb5509486ba77f32c39716c4d63bf86de6b808387a77") {
        throw Error("Expected PMK does not match. Got " + pmk.toString());
    }

    // Assert KCK is accurate.
    var kck = c.kckFromPmk(pmk);
    //if (kck !== "dc9471429e3918be1eff0f742450d0cd") {
    if (kck !== "dc9471429e3918be1eff0f742450d0cd") {
        throw Error("Expected KCK does not match. Got " + kck.toString());
    }

    var mic = c.micFromKck(kck);
    if (mic !== handshake.mic) {
        throw Error("Expected MIC does not match. Got " + mic);
    }

    Crack.debug("Crack.test_WPA2 passed.");
};

