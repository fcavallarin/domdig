const htcrawl = require('htcrawl');
const utils = require('./utils');
const defpayloads = require('./payloads').all;

const PAYLOADMAP = {};
const VULNSJAR = [];
var VERBOSE = true;
var PREVURL = null;

function getNewPayload(payload, element){
	const k = "" + Math.floor(Math.random()*4000000000);
	const p = payload.replace("{0}", k);
	PAYLOADMAP[k] = {payload:payload, element:element};
	return p;
}

async function crawlAndFuzz(targetUrl, payload, options){
	var hashSet = false;

	// instantiate htcrawl
	const crawler = await htcrawl.launch(targetUrl, options);

	// set a sink on page scope
	crawler.page().exposeFunction("___xssSink", function(key) {
		var url = "";
		if(crawler.page().url() != PREVURL){
			url = PREVURL = crawler.page().url();
		}
		utils.addVulnerability(PAYLOADMAP[key], VULNSJAR, url, VERBOSE);
	});

	// fill all inputs with a payload
	crawler.on("fillinput", async function(e, crawler){
		const p = getNewPayload(payload, e.params.element);
		try{
			await crawler.page().$eval(e.params.element, (i, p) => i.value = p, p);
		}catch(e){}
		// return false to prevent element to be automatically filled with a random value
		return false;
	});


	// change page hash before the triggering of the first event
	crawler.on("triggerevent", async function(e, crawler){
		if(!hashSet){
			const p = getNewPayload(payload, "hash");
			await crawler.page().evaluate(p => document.location.hash = p, p);
			hashSet = true;
			PREVURL = crawler.page().url();
		}
	});

	try{
		await crawler.load();
	} catch(e){
		console.log(`Error ${e}`);
		process.exit(-3);
	}

	PREVURL = crawler.page().url();

	if(options.initSequence){
		let seqline = 1;
		for(let seq of options.initSequence){
			switch(seq[0]){
				case "sleep":
					await crawler.page().waitFor(seq[1]);
					break;
				case "write":
					try{
						await crawler.page().type(seq[1], seq[2]);
					} catch(e){
						utils.sequenceError("element not found", seqline);
					}
					break;
				case "click":
					try{
						await crawler.page().click(seq[1]);
					} catch(e){
						utils.sequenceError("element not found", seqline);
					}
					await crawler.waitForRequestsCompletion();
					break;
				case "clickToNavigate":
					try{
						await crawler.clickToNavigate(seq[1], seq[2]);
					} catch(err){
						utils.sequenceError(err, seqline);
					}
					break;
				default:
					utils.sequenceError("action not found", seqline);
			}
			seqline++;
		}
	}


	try{
		await crawler.start();
	} catch(e){
		console.log(`Error ${e}`);
		process.exit(-4);
	}
	try{
		await crawler.reload();
	}catch(e){
		utils.error(e);
	}
	await crawler.page().waitFor(200);
	crawler.browser().close();
}

function ps(message){
	if(VERBOSE)utils.printStatus(message);
}

(async () => {
	const argv = require('minimist')(process.argv.slice(2), {boolean:["l", "J", "q"]});
	if(argv.q)VERBOSE = false;
	if(VERBOSE)utils.banner();
	if('h' in argv){
		utils.usage();
		process.exit(0);
	}

	const targetUrl = argv._[0];
	const options = utils.parseArgs(argv);

	if(!targetUrl){
		utils.usage();
		process.exit(1);
	}
	var payloads = argv.P ? utils.loadPayloadsFromFile(argv.P) : defpayloads;
	ps("starting scan");
	let cnt = 1;
	for(let payload of payloads){
		ps("crawling page");
		await crawlAndFuzz(targetUrl, payload, options);
		ps(cnt + "/" + payloads.length + " payloads checked");
		cnt++;
	}

	if(VERBOSE)console.log("");
	ps("scan finished, tot vulnerabilities: " + VULNSJAR.length);

	if(argv.J){
		console.log(utils.prettifyJson(VULNSJAR));
	} else if(VERBOSE){
		for(let v of VULNSJAR){
			utils.printVulnerability(v[0], v[1], v[2]);
		}
	}

	if(argv.o){
		let fn = utils.writeJSON(argv.o, VULNSJAR);
		ps("findings saved to " + fn)
	}
	process.exit(0);
})();
