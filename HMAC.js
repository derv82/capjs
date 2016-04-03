// http://sid.rstack.org/pres/0810_BACon_WPA2_en.pdf
var Hmac = {};

Hmac.zeroPad = function(text, length) {
    while (text.length < length) {
        text += "0";
    }
    return text;
};

Hmac.xor = function(first, second) {
    // TODO fix this crap.
    var result = ByteBuffer.allocate(first.length).put;
    for (var i = 0; i < first.length; i++) {
        var firstC = first.charCodeAt(first);
        result.push(firstC ^ second);
    }
    return result.join("");
};
Hmac.hash = function(secret, value) {
    var bi = bo = Hmac.zeroPad(secret);
};
