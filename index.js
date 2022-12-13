import * as server from "./server.js";
import * as client from "./client.js";
import { prefix } from "./log.js";


const log = prefix("[browser]");

function buildCredential(credential, user) {
	let li = document.createElement("li");
	li.append(credential.id.substring(0, 8) + "…", document.createElement("br"));

	let remove = document.createElement("button");
	remove.textContent = "Smazat klíč";
	remove.addEventListener("click", async e => {
		if (!confirm("O'RLY?")) { return; }
		await server.removeKey(user.id, credential.id);
		syncUsers();
	});
	li.append(remove);

	let login = document.createElement("button");
	login.textContent = "Ověřit";
	li.append(login);
	login.addEventListener("click", async _ => client.login(user.id, credential.id));

	return li;
}

function buildUser(user) {
	let li = document.createElement("li");
	li.append(`${user.name} (${user.id})`, document.createElement("br"));

	let remove = document.createElement("button");
	remove.textContent = "Smazat uživatele";
	remove.addEventListener("click", async e => {
		if (!confirm("O'RLY?")) { return; }
		await server.removeUser(user.id);
		syncUsers();
	});
	li.append(remove);

	let reg = document.createElement("button");
	reg.textContent = "Nové zařízení";
	li.append(reg);
	reg.addEventListener("click", async _ => {
		await client.register(user.id);
		syncUsers();
	});

	let login = document.createElement("button");
	login.textContent = "Ověřit";
	li.append(login);
	login.addEventListener("click", async _ => client.login(user.id));

	let creds = document.createElement("ul");
	li.append(creds);

	creds.append(...user.credentials.map(c => buildCredential(c, user)));

	return li;
}

async function syncUsers() {
	let users = await server.listUsers();
	let ul = document.querySelector("#users");
	ul.innerHTML = "";
	ul.append(...users.map(buildUser));
}

function featureTest(feature, label) {
	let node = log.log(label);
	node.classList.add(feature ? "ok" : "error");
}

async function init() {
	await server.init();

	document.querySelector("[name=register]").addEventListener("click", async _ => {
		await client.register();
		syncUsers();
	});
	document.querySelector("[name=login]").addEventListener("click", _ => client.login());

	syncUsers();

	featureTest(navigator.credentials, "CredentialsContainer");
	featureTest(window.PublicKeyCredential, "PublicKeyCredential");
	featureTest(window.AuthenticatorAttestationResponse, "AuthenticatorAttestationResponse");
	featureTest(AuthenticatorAttestationResponse.prototype.getPublicKey, "getPublicKey");
	featureTest(AuthenticatorAttestationResponse.prototype.getTransports, "getTransports");

	let avail = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
	featureTest(avail, "isUserVerifyingPlatformAuthenticatorAvailable");
}

init();
