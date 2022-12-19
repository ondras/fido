import { prefix } from "./log.js";import * as CBOR from "./cbor.js";
import * as base64 from "./base64.js";


const log = prefix("[server]");

const RP = {
	name: "Ondrášek"
}

const LS_KEY = "fido.users";
let users;

function findUser(id) {
	return users.find(user => user.id == id);
}

function storeUsers() {
	let str = JSON.stringify(users);
	localStorage.setItem(LS_KEY, str);
	log.log("user database saved");
}

export async function validate(uid, credential) {
	let user = findUser(uid);
	if (!user) {
		log.log("cannot find user with uid", uid);
		return false;
	}
	log.log("user", user.name);

	const { response } = credential;

	let cred = user.credentials.find(c => c.id == credential.id);
	let pk = base64.decode(cred.pk);
	log.log("validating signature for uid", uid, "cid", cred.id);

	let signature = response.signature;
	// console.log("SIGNATURE", signature)

	let clientDataJSON = response.clientDataJSON;
	// console.log("clientDataJSON", clientDataJSON)

	let authenticatorData = new Uint8Array(response.authenticatorData);
	// console.log("authenticatorData", authenticatorData)

	let clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON));
	// console.log("clientDataHash", clientDataHash)

	// concat authenticatorData and clientDataHash
	let signedData = new Uint8Array(authenticatorData.length + clientDataHash.length);
	signedData.set(authenticatorData);
	signedData.set(clientDataHash, authenticatorData.length);
	// console.log("signedData", signedData)

	// import key
	let key = await crypto.subtle.importKey("spki", pk, {
			name: "ECDSA",
			namedCurve: "P-256",
			hash: { name: "SHA-256" }
		}, false, ["verify"]
	);

	// Convert signature from ASN.1 sequence to "raw" format
	let usignature = new Uint8Array(signature);
	let rStart = usignature[4] === 0 ? 5 : 4;
	let rEnd = rStart + 32;
	let sStart = usignature[rEnd + 2] === 0 ? rEnd + 3 : rEnd + 2;
	let r = usignature.slice(rStart, rEnd);
	let s = usignature.slice(sStart);
	let rawSignature = new Uint8Array([...r, ...s]);

	// check signature with public key and signed data
	let verified = await crypto.subtle.verify(
		{ name: "ECDSA", namedCurve: "P-256", hash: { name: "SHA-256" } },
		key,
		rawSignature,
		signedData.buffer
	);

	log.log(verified ? "verification DONE :-)" : "verification FAILED :-(");

	return verified;
}

export async function register(id, name, credential) {
	let user = findUser(id);
	if (user) {
		log.log("user", user.name);
	} else {
		log.log("creating new user");
		user = {
			id,
			name,
			credentials: []
		}
		users.push(user);
	}

	const { response } = credential;
	const { credProps } = credential.getClientExtensionResults()
	if (credProps && credProps.rk) {
		log.log("the key IS a resident key :-)")
	} else {
		log.log("the key IS NOT a resident key :-(")
	}

	let pk = "";
	if (response.getPublicKey) {
		let pkAB = response.getPublicKey();
		pk = base64.encode(new Uint8Array(pkAB));
	}

	if (response.getTransports) {
		log.log("transports", response.getTransports());
	}

	log.log("adding new credential", credential.id, pk);
	user.credentials.push({id:credential.id, pk});
	storeUsers();

	/*
	const utf8Decoder = new TextDecoder("utf-8");
	const decodedClientData = utf8Decoder.decode(response.clientDataJSON);
	const clientDataObj = JSON.parse(decodedClientData);
	console.log("clientDataObj", clientDataObj);

	const decodedAttestationObj = CBOR.decode(response.attestationObject);
	console.log("decodedAttestationObj", decodedAttestationObj)
	const {authData} = decodedAttestationObj;

	// get the length of the credential ID
	const dataView = new DataView(new ArrayBuffer(2));
	const idLenBytes = authData.slice(53, 55);
	idLenBytes.forEach((value, index) => dataView.setUint8(index, value));
	const credentialIdLength = dataView.getUint16();

	// get the credential ID
	const credentialId = authData.slice(55, 55 + credentialIdLength);
	console.log("credentialId", credentialId)

	// get the public key object
	const publicKeyBytes = authData.slice(55 + credentialIdLength);

	// the publicKeyBytes are encoded again as CBOR
	const publicKeyObject = CBOR.decode(publicKeyBytes.buffer);
	console.log("publicKey", publicKeyObject);
	*/
}

export async function listUsers() {
	return users;
}

export async function removeUser(id) {
	log.log("removing user", id);
	users = users.filter(user => user.id != id);
	storeUsers();
}

export async function removeKey(uid, cid) {
	log.log("removing credential", cid, "from user", uid);
	let user = findUser(uid);
	user.credentials = user.credentials.filter(c => c.id != cid);
	storeUsers();
}

export async function getRegistrationOptions(id, name) {
	let challenge = new Uint8Array(16);
	crypto.getRandomValues(challenge);

	let excludeCredentials = [];

	let user = findUser(id);
	if (user) {
		excludeCredentials = user.credentials.map(credential => {
			return {id:credential.id, type:"public-key"}
		})
	} else {
		let id = new Uint8Array(8);
		crypto.getRandomValues(id);
		user = {
			id: base64.encode(id),
			name
		}
	}

	return {
		rp: RP,
		user: {
			id: user.id,
			name: user.name,
			displayName: user.name.split("@")[0]
		},
		extensions: { "credProps": true },
		excludeCredentials,
		challenge: base64.encode(challenge),
		pubKeyCredParams: [{alg: -7, type: "public-key"}],
		/*
		authenticatorSelection: {
			authenticatorAttachment: "cross-platform",
		},
		timeout: 60000,
		attestation: "direct"
		*/
	};
}

export async function getVerificationOptions(uid, cid) {
	let challenge = new Uint8Array(16);
	crypto.getRandomValues(challenge);

	let allowCredentials = [];

	let user = (uid ? findUser(uid) : null);
	if (user) {
		allowCredentials = user.credentials.map(c => {
			return {id:c.id, type:"public-key"}
		});
	} else if (cid) {
		allowCredentials.push(
			{id:cid, type:"public-key"}
		);
	}

	return {
		challenge: base64.encode(challenge),
		allowCredentials,
		/*
		authenticatorSelection: {
			authenticatorAttachment: "cross-platform",
		},
		timeout: 60000,
		attestation: "direct"
		*/
	};
}

export async function init() {
	let stored = localStorage.getItem(LS_KEY);
	if (stored) {
		users = JSON.parse(stored);
	} else {
		users = [];
	}
}
