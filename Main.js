// Debug
var textArea = document.querySelector("#debug");
textArea.value = "";

function debug(txt) {
    if (textArea.value !== '') {
        textArea.value += "\n";
    }
    textArea.value += txt;
    textArea.scrollTop = textArea.scrollHeight;
}


// Cap file viewer
function prettyTime(date) {
    var result = "", temp;

    result += date.getFullYear();
    result += "-";

    temp = (date.getMonth() + 1).toString();
    while (temp.length < 2) temp = "0" + temp;
    result += temp;
    result += "-";

    temp = date.getDate().toString();
    while (temp.length < 2) temp = "0" + temp;
    result += temp;

    result += "T";

    temp = date.getHours().toString();
    while (temp.length < 2) temp = "0" + temp;
    result += temp;

    result += ":";

    temp = date.getMinutes().toString();
    while (temp.length < 2) temp = "0" + temp;
    result += temp;

    result += ":";

    temp = date.getSeconds().toString();
    while (temp.length < 2) temp = "0" + temp;
    result += temp;

    result += ".";

    temp = date.getMilliseconds().toString();
    while (temp.length < 3) temp = "0" + temp;
    result += temp;

    return result;
}

function prettyMac(mac) {
    var result = "", i;
    for (i = 0; i < mac.length; i += 2) {
        if (result !== "") {
            result = result + ":";
        }
        result += mac.substring(i, i + 2).toUpperCase();
    }
    return result;
}

function prettyFrame(frame) {
    var tr = document.createElement("tr");
    var td = document.createElement("td");
    td.className = "prettyFrame";
    td.colSpan = 8;
    var pre = document.createElement("pre");
    pre.className = "payload";
    pre.textContent = JSON.stringify(frame, null, 2);
    td.appendChild(pre);
    tr.appendChild(td);
    return tr;
}

function prettyClick(row, frame) {
    row.addEventListener('click', function() {
        if (this.className === "collapsed") {
            this.querySelector(".expando").textContent = "-";
            this.className = "expanded";
            this.parentNode.insertBefore(prettyFrame(frame), this.nextSibling);
            this.scrollIntoView();
        } else if (this.className === "expanded") {
            this.querySelector(".expando").textContent = "+";
            document.querySelector(".prettyFrame").remove();
            this.className = "collapsed";
        }
    }, false);
}

function loadCapfile(capfile) {
    var tbody = document.querySelector("#capfileBody");
    for (var i = 0; i < capfile.packetFrames.length; i++) {
        var frame = capfile.packetFrames[i];
        var tr = document.createElement("tr");
        tr.className = "collapsed";
        var td;

        td = document.createElement("td");
        td.className = "expando";
        td.textContent = "+";
        tr.appendChild(td);

        // Frame #
        td = document.createElement("td");
        td.className = "index";
        td.textContent = (i + 1);
        tr.appendChild(td);

        // Timestamp
        td = document.createElement("td");
        td.textContent = prettyTime(frame.header.timestamp);
        tr.appendChild(td);

        // Source Address
        td = document.createElement("td");
        td.textContent = prettyMac(frame.addr2);
        tr.appendChild(td);

        // Destination Address
        td = document.createElement("td");
        td.textContent = prettyMac(frame.addr1);
        tr.appendChild(td);

        // Size
        td = document.createElement("td");
        td.textContent = frame.header.length;
        tr.appendChild(td);

        // Type
        td = document.createElement("td");
        var name = frame.name;
        if (frame.description) {
            frame.name += " - " + frame.description;
        }
        td.textContent = frame.name;
        tr.appendChild(td);

        prettyClick(tr, frame);
        tbody.appendChild(tr);
    }
}

// FileChooser
document.querySelector('#fileChooser').addEventListener('change', function() {
    var reader = new FileReader();
    reader.onload = function(){
        var capfile = new CapFile(this.result, debug);
        loadCapfile(capfile);
        //document.querySelector('#result').innerHTML = JSON.stringify(capfile, null, 2);
    }
    reader.readAsBinaryString(this.files[0]);
}, false);

// Test buttons
document.querySelector("#test1").addEventListener('click', function() {
    Crack.test_WPA1(debug);
}, false);
document.querySelector("#test2").addEventListener('click', function() {
    Crack.test_WPA2(debug);
}, false);
