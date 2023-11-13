
const qryCreateTableRequest = `
	CREATE TABLE request (
		id INTEGER PRIMARY KEY AUTOINCREMENT, 
		type TEXT,
		method TEXT,
		url TEXT,
		headers TEXT,
		data TEXT,
		trigger TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)
`;

const qryCreateTableScanInfo = `
	CREATE TABLE scan_info (
		id INTEGER PRIMARY KEY AUTOINCREMENT, 
		status TEXT,
		completed BOOLEAN NOT NULL DEFAULT false,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)
`;

const qryCreateTableVulnerability = `
	CREATE TABLE vulnerability (
		id INTEGER PRIMARY KEY AUTOINCREMENT, 
		type TEXT,
		description TEXT,
		element TEXT,
		payload TEXT,
		url TEXT,
		confirmed BOOLEAN,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)
`;

const qryCreateTableScanSettings = `
	CREATE TABLE scan_settings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		parameter TEXT,
		value TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)
`;

exports.Database = class {
	constructor(dbName){
		this.dbName = dbName;
	}

	connect(){
		return require('better-sqlite3')(this.dbName);
	}

	run(qry, pars){
		const db = this.connect();
		if(pars){
			for(let i = 0; i < pars.length; i++){
				if(typeof pars[i] == 'boolean'){
					pars[i] = pars[i] ? 1 : 0;
				}
			}
		}
		const ret = db.prepare(qry).run(pars);
		db.close();
		return ret;
	}

	init(){
		const db = this.connect();
		db.exec(qryCreateTableRequest);
		db.exec(qryCreateTableScanInfo);
		db.exec(qryCreateTableVulnerability);
		db.exec(qryCreateTableScanSettings);
		db.close();
	}

	updateStatus(status, completed){
		this.run("INSERT INTO scan_info (status, completed) values (?, ?)", [status, completed]);
	}

	addRequest(request){
		const qry = "INSERT INTO request (type, method, url, headers, data, trigger) values (?, ?, ?, ?, ?, ?)";
		this.run(qry, [request.type, request.method, request.url, JSON.stringify(request.extra_headers), request.data, JSON.stringify(request.trigger)]);
	}

	addVulnerability(vulnerability){
		const qry = "INSERT INTO vulnerability (type, description, element, payload, url, confirmed) values (?, ?, ?, ?, ?, ?)";
		this.run(qry, [vulnerability.type, vulnerability.message, vulnerability.element, vulnerability.payload, vulnerability.url, vulnerability.confirmed]);
	}

	updateVulnerability(vulnerability){
		const qry = "UPDATE vulnerability set confirmed=? where type=? and payload=? and element=? and url=?";
		this.run(qry, [vulnerability.confirmed, vulnerability.type, vulnerability.payload, vulnerability.element, vulnerability.url]);
	}

	addScanArguments(args){
		const qry = "INSERT INTO scan_settings (parameter, value) values (?, ?)";
		for(const arg of args){
			this.run(qry, arg);
		}
	}
}
