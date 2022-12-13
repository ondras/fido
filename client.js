import * as server from "./server.js";
import { prefix } from "./log.js";
import * as base64 from "./base64.js";


const log = prefix("[client]");
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

export async function register(id=null) {
	log.clear();

	log.log("Starting registration for id");
	await sleep(10);

	let email;
	if (!id) {
		email = prompt("New user's email", "a@b.cz");
		if (email === null) {
			log.log("cancelled");
			return;
		}
		log.log("got email", email);
		await sleep(10);
	}

	try {
		let publicKey = await server.getRegistrationOptions(id, email);
		log.log("got options", publicKey);
		id = publicKey.user.id;

		publicKey.challenge = base64.decode(publicKey.challenge);
		publicKey.user.id = base64.decode(publicKey.user.id);
		publicKey.excludeCredentials.forEach(c => c.id = base64.decode(c.id))

		let authenticatorSelection = {};
		let userVerification = document.querySelector("[name=userVerification]").value;
		if (userVerification) { authenticatorSelection.userVerification = userVerification; }
		let authenticatorAttachment = document.querySelector("[name=authenticatorAttachment]").value;
		if (authenticatorAttachment) { authenticatorSelection.authenticatorAttachment = authenticatorAttachment; }
		let residentKey = document.querySelector("[name=residentKey]").value;
		if (residentKey) { authenticatorSelection.residentKey = residentKey; }

		publicKey.authenticatorSelection = authenticatorSelection;
		console.log(publicKey)

		let credential = await navigator.credentials.create({publicKey});
		log.log("got credential", credential);

		await server.register(id, email, credential);
		log.log("done");
	} catch (e) {
		log.log(e);
	}
}

export async function login(uid=null, cid=null) {
	log.clear();

	log.log("Starting verification for user", uid, "credential", cid);
	await sleep(10);


	try {
		let publicKey = await server.getVerificationOptions(uid, cid);
		log.log("got options", publicKey);

		let userVerification = document.querySelector("[name=userVerification]").value;
		if (userVerification) { publicKey.userVerification = userVerification; }

		publicKey.challenge = base64.decode(publicKey.challenge);
		publicKey.allowCredentials.forEach(c => c.id = base64.decode(c.id))
		console.log(publicKey)

		let credential = await navigator.credentials.get({publicKey});
		log.log("got credential", credential);
		if (credential.response.userHandle) {
			uid = base64.encode(new Uint8Array(credential.response.userHandle));
		}

		await server.validate(uid, credential);
		log.log("done");
	} catch (e) {
		log.log(e);
	}
}
