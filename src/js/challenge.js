let TRANSLATIONS;

function __(key) {
	let replacement = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : null;
	const translation = TRANSLATIONS[key] || key;
	return replacement !== null ? translation.replace('%s', replacement) : translation;
}

function updateElem(selector, text, color) {
	const updateElem = document.querySelector(selector);
	if (updateElem) {
		updateElem.innerText = text;
		if (color) {
			updateElem.style.color = color;
		}
	}
}

function insertError(str) {
	const loader = document.querySelector("#loader");
	const captcha = document.querySelector("#captcha");
	(captcha || loader).insertAdjacentHTML(
		"afterend",
		`<p class="red">Error: ${str}</p>`,
	);
	loader && loader.remove();
	captcha && captcha.remove();
	updateElem(".powstatus", "");
}

function finishRedirect() {
	window.location = location.search.slice(1) + location.hash || "/";
}

function makeLoaderGreen() {
	const dots = document.querySelectorAll(".b");
	if (dots && dots.length > 0) {
		dots.forEach((dot) => dot.classList.add("green"));
	}
}

const wasmSupported = (() => {
	try {
		if (
			typeof WebAssembly === "object" &&
			typeof WebAssembly.instantiate === "function"
		) {
			const module = new WebAssembly.Module(
				Uint8Array.of(0x0, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00),
			);
			if (module instanceof WebAssembly.Module) {
				return new WebAssembly.Instance(module) instanceof WebAssembly.Instance;
			}
		}
	} catch (e) {
		console.error(e);
	}
	return false;
})();

// const registerServiceWorker = async () => {
	// if ("serviceWorker" in navigator) {
		// try {
			// const registration = await navigator.serviceWorker.register("/.basedflare/js/serviceworker.min.js", {
				// scope: "/",
			// });
			// if (registration.installing) {
				// console.log("BasedFlare service worker installing");
			// } else if (registration.waiting) {
				// console.log("BasedFlare service worker installed");
			// } else if (registration.active) {
				// console.log("BasedFlare service worker active");
			// }
		// } catch (error) {
			// console.error(`BasedFlare worker registration failed: ${error}`);
		// }
	// }
// };

function clearCookiesForDomains(domain) {
	const parts = ['www', ...domain.split('.')];
	for (let i = 0; i < parts.length - 1; i++) {
		const subdomain = parts.slice(i).join('.');
		document.cookie = `_basedflare_pow=; Max-Age=-9999999; Path=/; Domain=.${subdomain}`;
		document.cookie = `_basedflare_captcha=; Max-Age=-9999999; Path=/; Domain=.${subdomain}`;
	}
	location.reload();
}

function postResponse(powResponse, captchaResponse) {
	const body = {
		"pow_response": powResponse,
	};
	if (captchaResponse) {
		body["h-captcha-response"] = captchaResponse;
		body["g-recaptcha-response"] = captchaResponse;
	}
	fetch("/.basedflare/bot-check", {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
		},
		body: new URLSearchParams(body),
		redirect: "manual",
	}).then((res) => {
		const s = res.status;
		if (s >= 400 && s < 500) {
			clearCookiesForDomains(location.hostname);
			return insertError(__("Server rejected your submission."));
		} else if (s >= 500) {
			return insertError(__("Server encountered an error."));
		}
		window.localStorage.setItem("_basedflare-redirect", Math.random());
		finishRedirect();
	}).catch(() => {
		clearCookiesForDomains(location.hostname);
		insertError(__("Failed to send request to server."));
	});
}

const powFinished = new Promise((resolve) => {
	let start = Date.now();
	const workers = [];
	let finished = false;
	const stopPow = () => {
		finished = true;
		const hasCaptcha = document.getElementById("captcha");
		if (hasCaptcha) {
			// updateElem(".powstatus", __("Waiting for captcha."), "#31cc31");
		} else {
			// updateElem(".powstatus", __("Submitting..."), "#31cc31");
			makeLoaderGreen();
		}
		workers.forEach((w) => w.terminate());
	};
	const submitPow = (answer) => {
		window.localStorage.setItem("_basedflare-pow-response", answer);
		stopPow();
		const dummyTime = 3500 - (Date.now() - start);
		window.setTimeout(() => {
			resolve({
				answer
			});
		}, dummyTime);
	};

	window.addEventListener("DOMContentLoaded", async () => {
		TRANSLATIONS = JSON.parse(document.head.dataset.langjson);
		// registerServiceWorker();
		const {
			time,
			kb,
			pow,
			diff,
			mode
		} =
		document.querySelector("[data-pow]").dataset;
		window.addEventListener("storage", (event) => {
			if (event.key === "_basedflare-pow-response" && !finished) {
				console.log("Got answer", event.newValue, "from storage event");
				stopPow();
				resolve({
					answer: event.newValue,
					localStorage: true
				});
			} else if (event.key === "_basedflare-redirect") {
				console.log("Redirecting, solved in another tab");
				finishRedirect();
			}
		});

		if (mode === "argon2" && !wasmSupported) {
			return insertError(__("Browser does not support WebAssembly."));
		}
		const powOpts = {
			time: time,
			mem: kb,
			hashLen: 32,
			parallelism: 1,
			type: argon2 ? argon2.ArgonType.Argon2id : null,
			mode: mode,
		};
		console.log("Got pow", pow, "with difficulty", diff);
		const eHashes = Math.pow(16, Math.floor(diff / 8)) *
			(((diff % 8) * 2) || 1);
		const diffString = "0".repeat(Math.floor(diff / 8));
		const [userkey, challenge] = pow.split("#");
		if (window.Worker) {
			let cpuThreads;
			try {
				cpuThreads = window.navigator.hardwareConcurrency || 2;
			} catch(e) {
				//catch just in case, and potentially fix an issue w safari
				console.warn('navigator.hardwareConcurrency unavailable');
				cpuThreads = 2;
			}
			const isTor = location.hostname.endsWith(".onion");
			/* Try to use all threads on tor, because tor limits threads for anti fingerprinting but this
			   makes it awfully slow because workerThreads will always be = 1 */
			const workerThreads = (isTor || cpuThreads === 2) ?
				cpuThreads :
				Math.max(Math.ceil(cpuThreads / 2), cpuThreads - 1);
			const messageHandler = (e) => {
				if (e.data.length === 1) {
					const totalHashes = e.data[0]; //assumes all worker threads are same speed
					const elapsedSec = Math.floor((Date.now() - start) / 1000);
					const hps = Math.floor(totalHashes / elapsedSec);
					const requiredSec = Math.floor(eHashes / hps) * 1.5; //estimate 1.5x time
					const remainingSec = Math.max(
						0,
						Math.floor(requiredSec - elapsedSec),
					); //dont show negative time
					return console.log(`${hps}H/s, ≈${remainingSec}s remaining`);
					// return updateElem(
					// 	".powstatus",
					// 	__('Working, ≈%ss remaining', remainingSec),
					// );
				}
				if (finished) return;
				const [workerId, answer] = e.data;
				console.log(
					"Worker",
					workerId,
					"returned answer",
					answer,
					"in",
					Date.now() - start + "ms",
				);
				submitPow(`${pow}#${answer}`);
			};
			for (let i = 0; i < workerThreads; i++) {
				const powWorker = new Worker("/.basedflare/js/worker.min.js");
				powWorker.onmessage = messageHandler;
				workers.push(powWorker);
			}
			start = Date.now();
			for (let i = 0; i < workerThreads; i++) {
				await new Promise((res) => setTimeout(res, 10));
				workers[i].postMessage([
					userkey,
					challenge,
					diff,
					diffString,
					powOpts,
					i,
					workerThreads,
				]);
			}
		} else {
			return insertError(__("Browser does not support Web Workers."));
		}
	});
}).then((powResponse) => {
	const hasCaptchaForm = document.getElementById("captcha");
	if (!hasCaptchaForm && !powResponse.localStorage) {
		postResponse(powResponse.answer);
	}
	return powResponse.answer;
}).catch((e) => {
	console.error(e);
});

function onCaptchaSubmit(captchaResponse) {
	const captchaElem = document.querySelector("[data-sitekey]");
	// captchaElem.insertAdjacentHTML('afterend', `<div id="loader" class="loader"><div></div><div></div><div></div><div></div></div>`);
	captchaElem.insertAdjacentHTML(
		"afterend",
		`<div id="loader"><div class="b"></div><div class="b"></div><div class="b"></div></div>`,
	);
	captchaElem.remove();
	powFinished.then((powResponse) => {
		updateElem(".powstatus", __("Submitting..."), "#31cc31");
		makeLoaderGreen();
		postResponse(powResponse, captchaResponse);
	});
}
