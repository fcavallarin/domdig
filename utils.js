const consts = require("./consts");
const fs = require('fs');
const chalk = require('chalk');
const Database = require('./database').Database;

exports.usage = usage;
exports.banner = banner;
exports.parseArgs = parseArgs;
exports.error = error;
exports.addVulnerability = addVulnerability;
exports.printVulnerability = printVulnerability;
exports.printRequest = printRequest;
exports.printStatus = printStatus;
exports.printInfo = printInfo;
exports.printWarning = printWarning;
exports.printError = printError;
exports.writeJSON = writeJSON;
exports.prettifyJson = prettifyJson;
exports.loadPayloadsFromFile = loadPayloadsFromFile;
exports.error = error;
exports.Vulnerability = Vulnerability;
exports.replaceSinkName = replaceSinkName;
exports.sleep = sleep;


function Vulnerability(type, payload, element, url, message, confirmed){
	this.type = type;
	// this.payload_orig = payload;
	this.payload = replaceSinkName(payload);
	this.element = element || "N/A";
	// this.url_orig = url;
	this.confirmed = !(confirmed === false);
	// The URL that was set when the vulnerability was found.
	this.url = url ? replaceSinkName(url) : "";
	if(message){
		this.message = message;
	} else switch (type){
		case consts.VULNTYPE_DOM:
			this.message = "DOM XSS found";
			break;
		case consts.VULNTYPE_STORED:
			this.message = "Stored XSS found";
			break;
		case consts.VULNTYPE_TEMPLATEINJ:
			this.message = "Template injection found";
			break;
	}
}

Vulnerability.prototype.equals =  function(type, element, payload, url){
	return this.payload == payload && this.element == element  && this.type == type && this.url == url;
}

function replaceSinkName(str){
	return str.replace(new RegExp("window\\." + consts.SINKNAME + "\\(" + "(\\{0\\}|[0-9])+" + "\\)"), "alert(1)");
}

function getVulnerability(jar, vuln){
	for(let v of jar){
		if(v.equals(vuln.type, vuln.element, vuln.payload, vuln.url)){
			return v;
		}
	}
	return null;
}

function addVulnerability(jar, db, type, vuln, url, message, verbose, confirmed){
	message = message || null;
	const v = new Vulnerability(type, vuln.payload, vuln.element, url, message, confirmed);
	const existing = getVulnerability(jar, v);
	if(existing){
		if(type == consts.VULNTYPE_DOM){
			if(!existing.confirmed){
				existing.confirmed = confirmed;
			} else {
				// If there is the same vuln already confirmed, then do nothing
				return;
			}

			if(db){
				db.updateVulnerability(existing);
			}
		}
	} else {
		jar.push(v);

		if(verbose){
			printVulnerability(v);
		}
		if(db){
			db.addVulnerability(v);
		}
	}

}

function printVulnerability(v){
	const msg = [chalk.red('[!]'), `${v.message}: ${v.element} → ${v.payload}`];
	if(v.url){
		msg.push(`→ ${v.url}`);
	}
	if(!v.confirmed){
		msg.push(chalk.yellow("UNCONFIRMED"));
	}
	console.log(msg.join(" "));
}

function printRequest(req){
	var m = "[R] ";
	if(req.trigger && req.trigger.element){
		m += '$(' + chalk.green(req.trigger.element) + ').' + chalk.greenBright(`${req.trigger.event}()`) + " → ";
	}
	m += chalk.cyan(req.method) + " " + req.url;
	if(req.data){
		m += "\n"
		try{
			m += prettifyJson(JSON.parse(req.data));
		} catch(e){
			m += req.data;
		}
		m += "\n" + "-".repeat(96);
	}
	console.log(m);	
}

function printStatus(mess){
	console.log(chalk.green("[*] ") + mess);
}
function printInfo(mess){
	console.log(chalk.blue("[*] ") + mess);
}

function printWarning(mess){
	console.log(chalk.yellow("[!] ") + mess);
}

function printError(mess){
	console.log(chalk.red("[!] ") + mess);
}

function error(message){
	console.error(chalk.red(message));
	process.exit(1);
}

function banner(){
	const { version } = require(`${__dirname}/package.json`);
	console.log(chalk.yellow([
		"   ___  ____  __  ______  _",
		"  / _ \\/ __ \\/  |/  / _ \\(_)__ _",
		" / // / /_/ / /|_/ / // / / _ `/",
		"/____/\\____/_/  /_/____/_/\\_, /"
	].join("\n")));
	console.log(chalk.green(` ver ${version}               `) + chalk.yellow("/___/"));
	console.log(chalk.yellow("DOM XSS scanner for Single Page Applications"));
	console.log(chalk.blue("https://github.com/fcavallarin/domdig"));
	console.log("");
}

function usage(){
	console.log([
		"domdig [options] url",
		"Options:",
		"   -c COOKIES|PATH   set cookies. It can be a string in the form",
		"                     value=key separated by semicolon or JSON.",
		"                     If PATH is a valid readable file,",
		"                     COOKIES are read from that file",
		"   -A CREDENTIALS    username and password used for HTTP",
		"                     authentication separated by a colon",
		"   -x TIMEOUT        set maximum execution time in seconds for each payload",
		"   -U USERAGENT      set user agent",
		"   -R REFERER        set referer",
		"   -p PROXY          proxy string protocol:host:port",
		"                     protocol can be 'http' or 'socks5'",
		"   -l                do not run chrome in headless mode",
		"   -E HEADER         set extra http headers (ex -E foo=bar -E bar=foo or JSON)",
		"   -s SEQUENCE|PATH  set initial sequence (JSON)",
		"                     If PATH is a valid readable file,",
		"                     SEQUENCE is read from that file",
		"   -J                print findings as JSON",
		"   -q                quiet mode",
		"   -P PATH           load payloads from file (JSON)",
		"   -X REGEX          regular expression to eXclude urls (ex -X'.*logout.*' -X'.*signout.*')",
		"   -m MODES          comma-separated list of scan modes: domscan,fuzz (default: all)",
		"                        domscan  crawl the DOM injecting payloads into input values",
		"                        fuzz     fuzz the URL (query params and hash) with XSS payloads",
		"   -T                disabe template injection check",
		"   -S                disabe Stored XSS check",
		"   -g KEY/VALUE      set browser's Local/Session storaGe (ex -g L:foo=bar -g S:bar=foo or JSON)",
		"   -d FILE_NAME      save all the results to a SQLite3 database",
		"   -r                print all XHR/fetch and websocket requests triggered while scanning",
		"   -D                dry-run, do not use any payload, just crawl the page",
		"   -L FILE_NAME      run the Sequence Builder and save the sequnce to file",
		"   -O                do not crawl non same-origin frames",
		"   -i                interactive mode",
		"   -h                this help"
	].join("\n"));
}


function loadPayloadsFromFile(path){
	var payloads, pj;
	try{
		pj = fs.readFileSync(path);
	} catch(e){
		error("unable to read payloads file");
	}
	try{
		payloads = JSON.parse(pj);
	} catch(e){
		error("unable to decode payloads file");
	}
	return payloads;
}

function parseCookiesString(str, domain){
	var cookies = [];
	if(typeof str != 'string') str = "" + str;
	try{
		cookies = JSON.parse(str);
	}catch(e){
		for(let t of str.split(/; */)){
			let kv = t.split(/ *= */);
			cookies.push({name: kv[0], value:kv.slice(1).join("=").trim()});
		}
	}

	for(let c of cookies){
		if(!c.url && !c.domain){
			c.domain = domain;
		}
	}
	return cookies;
}


function parseArgs(args, url, database){
	const save = opt => {
		if(!database){
			return;
		}
		database.addScanArgument(opt);
	}
	const settings = [];
	const options = {};
	for(let arg in args){
		switch(arg){
			case "c":
				try{
					options.setCookies = parseCookiesString(fs.readFileSync(args[arg]), url.hostname);
				} catch(e){
					options.setCookies = parseCookiesString(args[arg], url.hostname);
				}
				settings.push([`-${arg}`, JSON.stringify(options.setCookies)]);
				break;
			case "A":
				var arr = args[arg].split(":");
				options.httpAuth = [arr[0], arr.slice(1).join(":")];
				settings.push([`-${arg}`, args[arg]]);
				break;
			case "x":
				options.maxExecTime = parseInt(args[arg]) * 1000;
				settings.push([`-${arg}`, args[arg]]);
				break;
			case "U":
				options.userAgent = args[arg];
				settings.push([`-${arg}`, args[arg]]);
				break;
			case "R":
				options.referer = args[arg];
				settings.push([`-${arg}`, args[arg]]);
				break;
			case "p":
				var tmp = args[arg].split(":");
				if(tmp.length > 2){
					options.proxy = tmp[0] + "://" + tmp[1] + ":" + tmp[2];
				} else {
					options.proxy = args[arg];
				}
				settings.push([`-${arg}`, args[arg]]);
				break;
			case "l":
				options.headlessChrome = !args[arg];
				if(!options.headlessChrome){
					options.openChromeDevtools = true;
				}
				if(args[arg]){
					settings.push([`-${arg}`, null]);
				}
				break;
			case "E":
				try {
					options.extraHeaders = JSON.parse(args[arg]);
				} catch(e){
					let hdrs = typeof args[arg] == 'string' ? [args[arg]] : args[arg];
					options.extraHeaders = {};
					for(let h of hdrs){
						let t = h.split("=");
						options.extraHeaders[t[0]] = t.slice(1).join("=");
					}
				}
				settings.push([`-${arg}`, JSON.stringify(options.extraHeaders)]);
				break;
			case "g":
				try {
					options.localStorage = [];
					let ls = JSON.parse(args[arg]);
					for(let s in ls){
						let t = s.split(":");
						if(t.length == 1){
							options.localStorage.push({type: "L", key: t[0], val: ls[s]});
						} else {
							options.localStorage.push({type: t[0] == "S" ? "S" : "L", key: t[1], val: ls[s]});
						}
					}
				} catch(e){
					let ls = typeof args[arg] == 'string' ? [args[arg]] : args[arg];
					options.localStorage = [];
					for(let l of ls){
						let t = l.split("=");
						let val = t.slice(1).join("=");
						t = t[0].split(":");
						let type = t[0];
						let key = t.slice(1).join(":");
						if(key == "" || ['S', 'L'].indexOf(type) == -1 || val == ""){
							console.error(chalk.red("Error parsing -g option"));
							process.exit(1);
						}
						options.localStorage.push({type:type, key:key, val:val});
					}
				}
				settings.push([`-${arg}`, args[arg]]);
				break;
			case "s":
				try{
					options.initSequence = JSON.parse(fs.readFileSync(args[arg]));
				} catch(e){
					try{
						options.initSequence = JSON.parse(args[arg]);
					}catch(e){
						console.error(chalk.red("JSON error in sequence"));
						process.exit(1);
					}
				}
				settings.push([`-${arg}`, JSON.stringify(options.initSequence)]);
				break;
			case "X":
				options.excludedUrls = typeof args[arg] == 'string' ? [args[arg]] : args[arg];
				settings.push([`-${arg}`, args[arg]]);
				break;
			case "d":
				options.databaseFileName = args[arg];
				settings.push([`-${arg}`, args[arg]]);
				break;
			case "r":
				options.printRequests = args[arg];
				if(args[arg]){
					settings.push([`-${arg}`, null]);
				}
				break;
			case "D":
				options.dryRun = args[arg];
				if(args[arg]){
					settings.push([`-${arg}`, null]);
				}
				break;
			case "S":
				options.scanStored = !args[arg];
				if(args[arg]){
					settings.push([`-${arg}`, null]);
				}
				break;
			case "T":
				options.checkTemplateInj = !args[arg];
				if(args[arg]){
					settings.push([`-${arg}`, null]);
				}
				break;
			case "L":
				options.sequenceBuilder = args[arg];
				if(args[arg]){
					settings.push([`-${arg}`, null]);
				}
				break;
			case "O":
				options.includeAllOrigins = !args[arg];
				if(args[arg]){
					settings.push([`-${arg}`, null]);
				}
				break;
			case "i":
				options.interactiveUI = args[arg];
				if(args[arg]){
					settings.push([`-${arg}`, null]);
				}
				break;
			case "J":
				options.printJson = args[arg];
				if(args[arg]){
					settings.push([`-${arg}`, null]);
				}
				break;
		}
	}
	return {
		options: options,
		settings: settings,
	}
}

function genFilename(fname){
	if(!fs.existsSync(fname)) return fname;
	const f = fname.split(".");
	const ext = f.slice(-1);
	const name = f.slice(0, f.length-1).join(".");
	var nf, cnt = 1;

	do {
		nf = name + "-" + (cnt++) + "." + ext;
	} while(fs.existsSync(nf));

	return nf;
}

function writeJSON(file, object){
	let fn = genFilename(file);
	fs.writeFileSync(fn, JSON.stringify(object));
	return fn;
}

function prettifyJson(obj, layer){
	var i, br
		out = "",
		pd = " ".repeat(2);
	if(!layer)layer = 1;

	switch(typeof obj){
		case "object":
			if(!obj){
				return chalk.red(obj);
			}
			if(obj.constructor == Array){
				br = ['[', ']'];
				for(i = 0; i < obj.length; i++){
					out += "\n" + pd.repeat(layer) + prettifyJson(obj[i], layer + 1);
					out += i < obj.length-1 ? "," : "" + "\n";
				}
			} else {
				br = ['{', '}'];
				var props = Object.keys(obj);
				for(i = 0; i < props.length; i++){
					out += "\n" + pd.repeat(layer) + '"' + chalk.red(props[i]) + '": ';
					out += prettifyJson(obj[props[i]], layer + 1);
					out += i < props.length-1 ? "," : "" + "\n";
				}
			}
			if(!out) return br.join("");
			// padding of prv layer to align the closing bracket
			return br[0] + out + pd.repeat(layer-1) + br[1];
		case "string":
			return chalk.blue(JSON.stringify(obj));
		case "number":
			return chalk.green(obj);
		case "boolean":
			return chalk.yellow(obj);
	}
	return  obj;
}

function sleep(n){
	return new Promise(resolve => {
		setTimeout(resolve, n);
	});
};
