
const node = document.querySelector("#log")


export function format(value) {
	let node = document.createElement("span");
	switch (true) {
		case value === null:
			node.textContent = "(null)";
		break;

		case value instanceof Error:
			node.classList.add("error");
			node.textContent = value.message;
		break;

		case value instanceof PublicKeyCredential:
			let obj = {
				id: value.id,
				type: value.type,
				response: {
					clientDataJSON: value.response.clientDataJSON,
					attestationObject: value.response.attestationObject,
					signature: value.response.signature
				}
			}
			return format(obj);
		break;

		case typeof(value) == "object":
			let button = document.createElement("button");
			let visible = false;
			let text = JSON.stringify(value, null, 2);
			let tn = document.createTextNode("");
			function sync() {
				tn.nodeValue = (visible ? text : "");
				button.textContent = (visible ? "−" : "+");
			}
			node.append(button, tn);
			button.addEventListener("click", e => {
				visible = !visible;
				sync();
			});
			sync();
		break;

		default:
			node.textContent = value;
		break;

	}
	return node;
}

export function clear() {
	node.innerHTML = "";
	console.log("---");
}

export function log(...args) {
	console.log(...args);
	let line = document.createElement("div");
	line.append(...args.map(format));
	node.append(line);

	return line;
}

export function prefix(prefix) {
	return {
		log: log.bind(null, prefix),
		clear
	}
}
