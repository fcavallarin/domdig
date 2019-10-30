const htcrawl = require('htcrawl');
const utils = require('./utils');
const defpayloads = require('./payloads').all;
const URL = require('url').URL;

const PAYLOADMAP = [];
var PAYLOADMAP_I = 0;
const VULNSJAR = [];
var VERBOSE = true;
var PREVURL = null;

function getNewPayload(payload, element){
	const p = payload.replace("{0}", PAYLOADMAP_I);
	PAYLOADMAP[PAYLOADMAP_I] = {payload:payload, element:element};
	PAYLOADMAP_I++;
	return p;
}

function getUrlMutations(url, payload){
	var nu = new URL(url.href);
	nu.hash = "#" + getNewPayload(payload, "hash");
	const muts = [nu];
	for(let p of url.searchParams.keys()){
		nu = new URL(url.href);
		nu.searchParams.set(p, getNewPayload(payload, "GET/" + p));
		muts.push(nu);
	}
	return muts;
}

async function scanAttributes(crawler){
	// use also 'srcdoc' since it can contain also esacped html: <iframe srcdoc="&lt;img src=1 onerror=alert(1)&gt;"></iframe>
	// content can have a "timer" so maybe is not executed in time
	const attrs = ["href", "action", "formaction", "srcdoc", "content"];
	for(let attr of attrs){
		const elems = await crawler.page().$$(`[${attr}]`);
		for(let e of elems){
			// must use evaluate since puppetteer cannot get non-standard attributes
			let val = await e.evaluate( (i,a) => i.getAttribute(a), attr);
			if(val.match("___xssSink") == null){
				continue;
			} else {
				let key = val.match(/\(([0-9]+)\)/)[1];
				let es = await utils.getElementSelector(e);
				utils.addVulnerability(PAYLOADMAP[key], VULNSJAR, null, VERBOSE, `Attribute '${attr}' of '${es}' set to payload`);
				break;
			}
		}
	}
}

async function triggerOnpaste(crawler){
	const elems = await crawler.page().$$('[onpaste]');
	for(let e of elems){
		await e.evaluate(i => {
			var evt = document.createEvent('HTMLEvents');
			evt.initEvent("paste", true, false);
			i.dispatchEvent(evt);
		});
	}
}

async function loadCrawler(targetUrl, payload, options, trackUrlChanges){
	var hashSet = false;

	// instantiate htcrawl
	const crawler = await htcrawl.launch(targetUrl, options);

	// set a sink on page scope
	crawler.page().exposeFunction("___xssSink", function(key) {
		var url = "";
		if(crawler.page().url() != PREVURL){
			url = PREVURL = crawler.page().url();
		}
		utils.addVulnerability(PAYLOADMAP[key], VULNSJAR, trackUrlChanges ? url : null, VERBOSE);
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

	return crawler;
}


async function scanDom(crawler, options){

	try{
		// workaround, fix it in htcrawl
		let timeo = setTimeout(function(){
			crawler.stop();
		}, options.maxExecTime);

		await crawler.start();
		clearTimeout(timeo);
	} catch(e){
		console.log(`Error ${e}`);
		process.exit(-4);
	}

}

async function close(crawler){
	await crawler.page().waitFor(200);
	crawler.browser().close();
}

function ps(message){
	if(VERBOSE)utils.printStatus(message);
}


(async () => {
	var targetUrl, cnt, crawler;
	const argv = require('minimist')(process.argv.slice(2), {boolean:["l", "J", "q"]});
	if(argv.q)VERBOSE = false;
	if(VERBOSE)utils.banner();
	if('h' in argv){
		utils.usage();
		process.exit(0);
	}

	if(argv._.length == 0){
		utils.usage();
		process.exit(1);
	}

	try{
		targetUrl = new URL(argv._[0]);
	} catch(e){
		utils.error(e);
	}

	const options = utils.parseArgs(argv, targetUrl);
	const checks = argv.C ? argv.C.split(",") : ['dom', 'reflected', 'stored'];
	var payloads = argv.P ? utils.loadPayloadsFromFile(argv.P) : defpayloads;
	ps("Starting scan");

	if(checks.indexOf("dom") != -1){
		cnt = 1;
		for(let payload of payloads){
			ps("Scanning DOM");
			crawler = await loadCrawler(targetUrl.href, payload, options, true);
			await scanDom(crawler, options);
			await triggerOnpaste(crawler);
			await scanAttributes(crawler);
			await close(crawler);
			ps(cnt + "/" + payloads.length + " payloads checked");
			cnt++;
		}
	}

	// check for reflected XSS
	if(checks.indexOf("reflected") != -1){
		cnt = 1;
		for(let payload of payloads){
			ps("Checking reflected");
			for(let mutUrl of getUrlMutations(targetUrl, payload)){
				crawler = await loadCrawler(mutUrl.href, payload, options);
				if((await crawler.page().content()).match("window.___xssSink") == null){
					ps("Parameter not reflected, skipping DOM scan");
				} else {
					await scanDom(crawler, options);
				}
				await scanAttributes(crawler);
				await triggerOnpaste(crawler);
				await close(crawler);
				ps(cnt + "/" + payloads.length + " payloads checked");
			}
			cnt++;
		}
	}

	if(VERBOSE)console.log("");
	ps("Scan finished, tot vulnerabilities: " + VULNSJAR.length);

	if(argv.J){
		console.log(utils.prettifyJson(VULNSJAR));
	} else if(VERBOSE){
		for(let v of VULNSJAR){
			utils.printVulnerability(v[0], v[1], v[2], v[3]);
		}
	}

	if(argv.o){
		let fn = utils.writeJSON(argv.o, VULNSJAR);
		ps("Findings saved to " + fn)
	}
	process.exit(0);
})();
