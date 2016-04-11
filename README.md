# CapFile.js & Crack.js
WLAN Pcap parser & WPA/2 PSK validator in Javascript

## CapFile.js

Converts raw `.cap` or `.pcap` file bytes into structured Javascript objects.

Only supports:

1. WLAN packet captures,
2. Parsing of certain frame types (Probe, Auth, EAPOL) -- other frame types are ignored.

```javascript
// Get rawBytes from *somewhere*, e.g. "file" input element, external address, etc.

var capfile = new CapFile(rawBytes);
>>> '[CapFile.js] Using Little-Endian byte-encoding due to magic number: 2712847316'
>>> '[CapFile.js] GlobalHeader (24 bytes):'
>>> '[CapFile.js]  d4 c3 b2 a1 02 00 04 00   00 00 00 00 00 00 00 00'
>>> '[CapFile.js]  ff 7f 00 00 69 00 00 00'
>>> '[CapFile.js] Parsed 20 known frames out of 20 total frames.'

// Metadata about .cap file
capfile.globalHeader
>>> Object {
>>>   version: "2.4",
>>>   gmtOffset: 0,
>>>   sigFigs: 0,
>>>   snapshotLength: 32767,
>>>   headerType: 105
>>> }

capfile.packetFrames.length
>>> 20

// First example packet is a "Beacon Response" containing the SSID of the Access Point.
JSON.stringify(capfile.packetFrames[0], null, 2);
{
  "header": {
    "timestamp": "2011-01-16T21:28:30.057Z",
    "length": 435,
    ...
  },
  "frameControl": {
    "type": 0,
    "subtype": 5,
    ...
  },
  "name": "Probe Response - SSID: NETGEAR2815",
  "_bssid": "002275ecf9c9",
  ...
  "taggedParameters": {
    "0": {
      "name": "SSID",
      "length": 7,
      "data": "NETGEAR2815"
    },
    ...
  },
}

// Last example packet is the 4th message in a 4-way handshake
JSON.stringify(capfile.packetFrames[19], null, 2);
{
  "header": {
    "timestamp": "2011-01-16T21:28:30.109Z",
    "length": 133,
  },
  "frameControl": {
    "type": 2,
    "subtype": 8,
    ...
  },
  "name": "EAPOL (QoS) - Handshake (4 of 4)",
  "_bssid": "002275ecf9c9",
  "_station": "f4ce46629c64",
  ...
  "auth": {
    "version": 1, // 802.1X-2001
    "keyInfoFlags": {
      "keyDescriptorVersion": 2, // WPA2 (HMAC-SHA1 MIC)
      "keyType": 1,
      "mic": true,
      "secure": true,
      ...
    }
    "keyMIC": "646debf34b677fbfd78c5724dc9ea442",
    "replayCounter": 2925,
    ...
  }
}

// Extract data from a 4-way handshake (neccessary to validate PSK in Crack.js)
capfile.extractPmkFields()
>>> Object {
  ssid: "NETGEAR2815",
  bssid: "002275ecf9c9",
  snonce: "da12c942e9dfcbe67068438f87cd4ce49b2…",
  anonce: "f5f5cd2ca691efe420224f466d3eb1633ef…",
  srcAddress: "f4ce46629c64",
  dstAddress: "002275ecf9c9",
  keyLength: 16,
  mic: "646debf34b677fbfd78c5724dc9ea442",
  eapolFrameBytes: "0103005f02030a00000000000000000b6dd…",
  keyDescriptorVersion: 2 // WPA2
}
```

## Crack.js

```javascript
// Extract relevant fields from 4-way handshake (from CapFile.js)
var handshake = capfile.extractPmkFields();

// Initialize Crack.js
var crack = new Crack(handshake);

// Validate the PSK ("dandelion" is the PSK used in the 4-way handshake)
crack.tryPSK("dandelion")
'[Crack.js] Constructing PMK using PDKDF2(psk:dandelion, ssid:NETGEAR2815)...'
'[Crack.js] PMK (Pairwise Master Key): 273c545d3be7e3fd4510fb5509486ba77f32c39716c4d63bf86de6b808387a77'
'[Crack.js] Constructing KCK using handshake values, Hmac-SHA1, and the PMK...'
'[Crack.js] KCK (Key-Confirmation Key) : dc9471429e3918be1eff0f742450d0cd'
'[Crack.js] EAPOL packet frame bytes: 0103005f02030a00000000000000000b6dda12c9...'
'[Crack.js] Using Hmac-SHA1 for computing WPA2 MIC'
'[Crack.js] Computed Mic (based on PMK & KCK): 646debf34b677fbfd78c5724dc9ea442'
'[Crack.js] Expected Mic (from Handshake packet): 646debf34b677fbfd78c5724dc9ea442'
>>> true

// Validate an incorrect PSK
crack.tryPSK("dandelioX")
'[Crack.js] Constructing PMK using PDKDF2(psk:dandelioX, ssid:NETGEAR2815)...'
'[Crack.js] PMK (Pairwise Master Key): 6dda13b1dec8170ce16b091f42c4558cdd7b26fb84de0b28ad11d049e8945a55'
'[Crack.js] Constructing KCK using handshake values, Hmac-SHA1, and the PMK...'
'[Crack.js] KCK (Key-Confirmation Key) : c9fa4a020370cc74dfa9a92a1412785c'
'[Crack.js] EAPOL packet frame bytes: 0103005f02030a00000000000000000b6dda12c9...'
'[Crack.js] Using Hmac-SHA1 for computing WPA2 MIC'
'[Crack.js] Computed Mic (based on PMK & KCK): 6fbf2e9382faeeca025e00ec88f1cac4'
'[Crack.js] Expected Mic (from Handshake packet): 646debf34b677fbfd78c5724dc9ea442'
>>> false
```
