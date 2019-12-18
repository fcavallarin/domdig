const consts = require("./consts");
const fs = require('fs');
const chalk = require('chalk');

exports.usage = usage;
exports.banner = banner;
exports.parseArgs = parseArgs;
exports.error = error;
exports.addVulnerability = addVulnerability;
exports.printVulnerability = printVulnerability;
exports.printStatus = printStatus;
exports.printInfo = printInfo;
exports.printWarning = printWarning;
exports.printError = printError;
exports.sequenceError = sequenceError;
exports.writeJSON = writeJSON;
exports.prettifyJson = prettifyJson;
exports.loadPayloadsFromFile = loadPayloadsFromFile;
exports.error = error;
exports.getElementSelector = getElementSelector;
exports.Vulnerability = Vulnerability;

function Vulnerability(type, payload, element, url, message){
	this.type = type;
	this.payload = payload;
	this.element = element || "N/A";
	this.url = url || "";
	if(message){
		this.message = message;
	} else switch (type){
		case consts.VULNTYPE_DOM:
			this.message = "DOM XSS found";
			break;
		case consts.VULNTYPE_REFLECTED:
			this.message = "Reflected DOM XSS found";
			break;
		case consts.VULNTYPE_STORED:
			this.message = "Stored XSS found";
		case consts.VULNTYPE_TEMPLATEINJ:
			this.message = "Template injection found";
			break;
	}
}

function addVulnerability(jar, type, vuln, url, message, verbose){
	message = message || null;
	p = vuln.payload.replace("window." + consts.SINKNAME + "({0})", "alert(1)");
	for(let e of jar){
		if(e.payload == p && e.element == vuln.element && e.type == type && (!message || e.message == message) && (!url || e.url == url)){
			return;
		}
	}
	const v = new Vulnerability(type, p, vuln.element, url, message);
	jar.push(v);
	if(verbose){
		printVulnerability(v);
	}
}

function printVulnerability(v){
	var msg = chalk.red('[!]') + ` ${v.message}: ${v.element} → ${v.payload}`;
	if(v.url){
		msg += " → " + v.url;
	}
	console.log(msg);
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
	console.log(chalk.yellow([
		"   ___  ____  __  ______  _",
		"  / _ \\/ __ \\/  |/  / _ \\(_)__ _",
		" / // / /_/ / /|_/ / // / / _ `/",
		"/____/\\____/_/  /_/____/_/\\_, /"
	].join("\n")));
	console.log(chalk.green(" ver 1.0.0               ") + chalk.yellow("/___/"));
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
		"   -E HEADER         set extra http headers (ex -E foo=bar -E bar=foo)",
		"   -s SEQUENCE|PATH  set initial sequence (JSON)",
		"                     If PATH is a valid readable file,",
		"                     SEQUENCE is read from that file",
		"   -o PATH           save findings to a JSON file",
		"   -J                print findings as JSON",
		"   -q                quiet mode",
		"   -P PATH           load payloads from file (JSON)",
		"   -C CHECKS         comma-separated list of checks: dom,reflected,stored (default: all)",
		"   -X REGEX          regular expression to eXclude urls (ex -X'.*logout.*' -X'.*signout.*')",
		"   -T                disabe template injection check",
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


function parseArgs(args, url){
	const options = {};
	for(let arg in args){
		switch(arg){
			case "c":
				try{
					options.setCookies = parseCookiesString(fs.readFileSync(args[arg]), url.hostname);
				} catch(e){
					options.setCookies = parseCookiesString(args[arg], url.hostname);
				}
				break;
			case "A":
				var arr = args[arg].split(":");
				options.httpAuth = [arr[0], arr.slice(1).join(":")];
				break;
			case "x":
				options.maxExecTime = parseInt(args[arg]) * 1000;
				break;
			case "U":
				options.userAgent = args[arg];
				break;
			case "R":
				options.referer = args[arg];
				break;
			case "p":
				var tmp = args[arg].split(":");
				if(tmp.length > 2){
					options.proxy = tmp[0] + "://" + tmp[1] + ":" + tmp[2];
				} else {
					options.proxy = args[arg];
				}
				break;
			case "l":
				options.headlessChrome = !args[arg];
				break;
			case "E":
				let hdrs = typeof args[arg] == 'string' ? [args[arg]] : args[arg];
				options.extraHeaders = {};
				for(let h of hdrs){
					let t = h.split("=");
					options.extraHeaders[t[0]] = t[1];
				}
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
				break;
			case "X":
				options.excludedUrls = typeof args[arg] == 'string' ? [args[arg]] : args[arg];
				break;
		}
	}
	return options;
}


function sequenceError(message, seqline){
	if(seqline){
		message = "action " + seqline + ": " + message;
	}
	console.error(chalk.red(message));
	process.exit(2);
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


async function getElementSelector(element){
	return await element.evaluate( i => {
		function gs(element){
			if(!element || !(element instanceof HTMLElement))
				return "";
			var name = element.nodeName.toLowerCase();
			var ret = [];
			var selector = ""
			var id = element.getAttribute("id");

			if(id && id.match(/^[a-z][a-z0-9\-_:\.]*$/i)){
				selector = "#" + id;
			} else {
				let p = element;
				let cnt = 1;
				while(p = p.previousSibling){
					if(p instanceof HTMLElement && p.nodeName.toLowerCase() == name){
						cnt++;
					}
				}
				selector = name + (cnt > 1 ? `:nth-of-type(${cnt})` : "");
				if(element != document.documentElement && name != "body" && element.parentNode){
					ret.push(gs(element.parentNode));
				}
			}
			ret.push(selector);
			return ret.join(" > ");
		}
		return gs(i);
	});
}