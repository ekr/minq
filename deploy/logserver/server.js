var express = require('express');
var fs = require('fs');
var readline = require('readline');
var connid_regex = /[0-9a-fA-F]+$/;

var app = express();

var port = process.env.PORT || 3000;

if (process.argv.len < 2) {
    console.log("Need to specify log file");
    return;
}
var file = process.argv[2];
console.log(file);

app.get('/:connid', function(request, response) {
    var connid = request.params.connid;
    if (!connid.match(connid_regex)) {
        response.status(400).send("Bogus connid (non-hex characters)");
        return;
    }

    if(connid.length < 4) {
        response.status(400).send("Bogus connid (too short)");
        return;
    }

    connid = connid.toLowerCase();
    
    var match = 'Conn: ' + connid + "_";
    var data = "<pre>";
    const rl = readline.createInterface({
        input: fs.createReadStream(file),
        terminal: false
    });
    rl.on('line', function(l) {
        if (l.search(match) != -1) {
            data += l;
            data += "\n";
        }
    });
    rl.on('close', function() {
        data += "</pre>";
        response.send(data);
    });
});

app.listen(port, function() {
    console.log("Listening on " + port);
    console.log("Logfile = " + file);
});
