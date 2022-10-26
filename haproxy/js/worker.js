importScripts('/js/argon2.js');

onmessage = async function(e) {
	const [userkey, challenge, diff, diffString, argonOpts, id, threads] = e.data;
	console.log('Worker thread', id, 'started');
	let i = id;
	if (id === 0) {
		setInterval(() => {
			postMessage([i]);
		}, 500);
	}
	while(true) {
		const hash = await argon2.hash({
			pass: challenge + i.toString(),
			salt: userkey,
			...argonOpts,
		});
		// This throttle seems to really help some browsers not stop the workers abruptly
		i % 10 === 0 && await new Promise(res => setTimeout(res, 10));
		if (hash.hashHex.startsWith(diffString)
			&& ((parseInt(hash.hashHex[diffString.length],16) &
				0xff >> (((diffString.length+1)*8)-diff)) === 0)) {
			console.log('Worker', id, 'found solution');
			postMessage([id, i]);
			break;
		}
		i+=threads;
	}
}
