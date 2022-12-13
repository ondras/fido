export function encode(bytes) {
	let str = String.fromCharCode(...bytes);
	return window.btoa(str);
}

export function decode(str) {
	str = str.replace(/-/g, '+').replace(/_/g, '/'); // b64url mayb?
	let bytes = window.atob(str).split("").map(c => c.charCodeAt(0));
	return new Uint8Array(bytes);
}

