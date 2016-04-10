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
 * @param debug (boolean, optional) Prints debug information to console. default: false.
 */
function Crack(handshake, debug) {
    if (debug) {
        Crack.debug = debug;
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
 * Compute prefix of one of the inputs to Pseudo-Random Function (PRF).
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
 * Psudo-Random Function to calculate PTK.
 * @param pmk (CryptoJS-encoded object) The PMK, calculated from Crack.pmk()
 * @return (string, hex) The first 16 bytes of the PTK.
 */
Crack.prototype.ptk = function(pmk) {
   var blen;
   if (this.handshake.keyDescriptorVersion === 1) {
       blen = 64;
   } else if (this.handshake.keyDescriptorVersion === 2) {
       blen = 32;
   }
    var i = 0, R = "", thisPrefix;
    while (i < (blen * 8 + 159) / 160) {
        console.log("Round", i + 1);
        thisPrefix = this.prfPrefix + "0" + i;

        thisPrefix = CryptoJS.enc.Hex.parse(thisPrefix);
        R += CryptoJS.HmacSHA1(thisPrefix, pmk).toString();

        i++;
    }
    // Extract first 16 bytes (32 hex characters) to get KCK.
    return R.substring(0, 32);
};

Crack.prototype.ptkToMic = function(ptk) {
    ptk = CryptoJS.enc.Hex.parse(ptk);
    var bytes = CryptoJS.enc.Hex.parse(this.handshake.eapolFrameBytes);
    console.log("EAPOL bytes", bytes.toString());
    var computedMic;
    if (this.handshake.keyDescriptorVersion === 1) {
        // Use HmacMD5 for WPA MIC
        computedMic = CryptoJS.HmacMD5(bytes, ptk).toString();
    }
    else if (this.handshake.keyDescriptorVersion === 2) {
        // Use HmacSHA1 for WPA2 MIC
        computedMic = CryptoJS.HmacSHA1(bytes, ptk).toString();
        computedMic = computedMic.substring(0, 32);
    }
    else {
        throw Error("Unknown key descriptor version: " + this.handshake.keyDescriptorVersion + ", expecting '1' or '2'");
    }
    console.log("computedMic", computedMic);
    console.log("expectedMic", this.handshake.mic);
}

/**
 * Calculates Pairwise Master Key (PMK) for using the given key.
 * @param key (string) The plaintext key/password.
 * @param ssid (string, optional) SSID (name of Access Point). Uses name from handshake file if not given.
 * @return (CryptoJS-encoded object) The PMK.
 */
Crack.prototype.pmk = function(key, ssid) {
    // Tribble
    //return CryptoJS.enc.Hex.parse("273c545d3be7e3fd4510fb5509486ba77f32c39716c4d63bf86de6b808387a77");

    // Netgear 2/158
    //return CryptoJS.enc.Hex.parse("01b809f9ab2fb5dc47984f52fb2d112e13d84ccb6b86d4a7193ec5299f851c48");

    if (Crack.debug) {
        console.log("[CapFile.js] Constructing PMK using PDKDF2(" + key + ", " + this.handshake.ssid + ")...");
    }
    var result = CryptoJS.PBKDF2(key, ssid || this.handshake.ssid, this.pbkdf2ConfigForPmk);
    return result;
};

