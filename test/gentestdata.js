const fs = require('fs');
const { spawn } = require('child_process');

const main = async page => {


    const db = require('better-sqlite3')(`${__dirname}/testdata.db`);
    const scanSettings = {
        command: db.prepare("SELECT parameter, value FROM scan_settings where parameter is null or (parameter != '-P' and parameter != '-d')").all().map(p => 
            [p.parameter, p.value].filter(v => !!v)
        ).flat(),
        payloads: db.prepare('SELECT * FROM vulnerability').all().map(v => 
            v.payload.replace(/alert\(1\)/g, 'window.___xssSink({0})')
        )
    }

    fs.writeFileSync(`${__dirname}/testdata/${page}.json`, JSON.stringify(scanSettings));
}

main(process.argv[2])