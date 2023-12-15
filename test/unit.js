const fs = require('fs');

const { spawn } = require('child_process');

function arrayCmp(arr1, arr2) {
    if (arr1.length !== arr2.length) return false;
    return arr1.slice().sort().every((value, index) => 
        value === arr2.slice().sort()[index]
    );
}


function runDomdig(cmd){
    return new Promise((resolve, reject) => {
        const child = spawn('node', ['../domdig.js', ...cmd]);
        child.stdout.on('data', (data) => {
        //   console.log(`${data}`);
        });
        
        child.stderr.on('data', (data) => {
          reject(`Errore standard: ${data}`);
        });
        
        child.on('close', (code) => {
          resolve(code);
        });
    })
};

tests = ["attributes","fetch","href","xhr","deep","hidden","postmessage"];

(async () => {
    for(const test of tests){
        if(process.argv[2] && process.argv[2] != test){
            continue;
        }
        const testData = require(`${__dirname}/testdata/${test}.json`);
        const dbFile = `${__dirname}/testout.db`;
        const payloadsFile = `${__dirname}/payloads.json`;
        try{
            fs.unlinkSync(dbFile);
        }catch(e){}
        fs.writeFileSync(payloadsFile, JSON.stringify(testData.payloads))
        const exitcode = await runDomdig([...testData.command, '-d', dbFile, '-P', payloadsFile]);


        const db = require('better-sqlite3')(dbFile);
        const payloads = db.prepare('SELECT * FROM vulnerability').all().map(v =>
            v.payload.replace(/alert\(1\)/g, 'window.___xssSink({0})')
        )
        if(!arrayCmp(testData.payloads, payloads)){
            console.log(`Test failed: ${test}`)
            console.log("Expected", testData.payloads);
            console.log("Got ", payloads);
            process.exit(1);
        }
        fs.unlinkSync(dbFile);
        fs.unlinkSync(payloadsFile);
    }
})();