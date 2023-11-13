function getHash(){
	return decodeURIComponent(document.location.hash.substr(1));
}

function setHash(h){
	document.location.href = document.location.href.split("#")[0] + "#" +h;
}