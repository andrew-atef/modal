export interface Env {
	VIDEO_KEYS: KVNamespace;
	ALLOWED_DOMAINS: string;
	ENVIRONMENT_SECRET: string;
	WAE?: AnalyticsEngineDataset;
}

interface AnalyticsEngineDataset {
	writeDataPoint(event?: {
		blobs?: (string | null)[];
		doubles?: (number | null)[];
		indexes?: (string | null)[];
	}): void;
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		const pathParts = url.pathname.split('/');
		
		if (request.method === 'OPTIONS') {
			return handleCors(request, env);
		}

		if (pathParts[1] !== 'keys' || !pathParts[2]) {
			return corsResponse('Not Found', 404, request, env);
		}
		const videoId = pathParts[2];

		const tokenVal = getCookie(request, 'video_auth') || url.searchParams.get('token');
		if (!tokenVal) {
			return corsResponse('Forbidden: Missing authentication token', 403, request, env);
		}

		const parts = tokenVal.split('.');
		if (parts.length !== 2) {
			return corsResponse('Forbidden: Invalid token format', 403, request, env);
		}

		const [payloadB64, signatureHex] = parts;

		const isValidHmac = await verifyHmac(payloadB64, signatureHex, env.ENVIRONMENT_SECRET);
		if (!isValidHmac) {
			return corsResponse('Forbidden: Tampered or invalid token signature', 403, request, env);
		}

		let payload: { video_id: string; tenant_id: string; exp: number; fingerprint: string; tlsFingerprint32?: string };
		try {
			payload = JSON.parse(base64UrlDecode(payloadB64));
		} catch (e) {
			return corsResponse('Forbidden: Invalid payload encoding', 403, request, env);
		}

		if (payload.exp && Date.now() / 1000 > payload.exp) {
			return corsResponse('Forbidden: Session cookie expired', 403, request, env);
		}

		if (payload.video_id !== videoId) {
			return corsResponse('Forbidden: Session mismatch for video', 403, request, env);
		}

		const currentFingerprint = generateFingerprint(request);
		if (payload.fingerprint !== currentFingerprint) {
			const storedParts = payload.fingerprint.split('|');
			const currentParts = currentFingerprint.split('|');
			
			if (storedParts.length >= 4 && currentParts.length >= 4) {
				const subnetMatch = storedParts[0] === currentParts[0];
				const countryMatch = storedParts[1] === currentParts[1] || storedParts[1] === 'XX';
				const asnMatch = storedParts[2] === currentParts[2] || storedParts[2] === '0000';
				const uaMatch = storedParts[3] === currentParts[3];

				if (subnetMatch && uaMatch && countryMatch && asnMatch) {
					console.log(`[Fingerprint Dev Match] Stored: ${payload.fingerprint} | Current: ${currentFingerprint}`);
				} else if (!subnetMatch && asnMatch && uaMatch && countryMatch) {
					console.warn(`[CGNAT Grace] Subnet changed from ${storedParts[0]} to ${currentParts[0]}`);
				} else {
					return corsResponse('Forbidden: Session fingerprint validation failed', 403, request, env);
				}
			} else {
				return corsResponse('Forbidden: Session fingerprint validation failed', 403, request, env);
			}
		}

		const clientTls = (request.cf as any)?.tlsClientHello?.tlsFingerprint32 || (request.cf as any)?.tlsFingerprint32;
		if (payload.tlsFingerprint32 && clientTls) {
			if (payload.tlsFingerprint32 !== clientTls) {
				return corsResponse('Forbidden: Automated bot or scraper detected (JA3 Mismatch)', 403, request, env);
			}
		}

		try {
			const kvKey = `video:${videoId}:keys`;
			const keyDataJson = await env.VIDEO_KEYS.get(kvKey);
			if (!keyDataJson) {
				return corsResponse('Not Found: Encryption keys not found', 404, request, env);
			}
			
			let keyData;
			try {
				keyData = JSON.parse(keyDataJson);
				if (typeof keyData === 'string') {
					keyData = JSON.parse(keyData);
				}
			} catch (parseError) {
				return corsResponse('Internal Server Error: Corrupt KV Data', 500, request, env);
			}

			if (env.WAE) {
				ctx.waitUntil((async () => {
					try {
						env.WAE!.writeDataPoint({
							blobs: [videoId, payload.tenant_id, 'AES-128']
						});
					} catch (aeError) {}
				})());
			}

			// إعداد الترويسات للرد الأصلي لـ CORS
			const headers = new Headers();
			const corsH = getCorsHeaders(request, env);
			for (const [k, v] of Object.entries(corsH)) {
				headers.set(k, v);
			}
			headers.set('Cache-Control', 'private, no-store');

			// --- التعديل الجوهري والنهائي هنا ---
			// لضمان عمل تشفير AES-128 على الـ iPhone والكمبيوتر وكل الأجهزة، يجب دائماً إرجاع المفتاح ثنائي (Binary) بطول 16 بايت
			const binaryKey = hexToUint8Array(keyData.key);
			headers.set('Content-Type', 'application/octet-stream');
			return new Response(binaryKey, { status: 200, headers });

		} catch (e) {
			return corsResponse('Internal Server Error', 500, request, env);
		}
	},
};

function corsResponse(body: string | null, status: number, request: Request, env: Env): Response {
	const headers = new Headers();
	const corsH = getCorsHeaders(request, env);
	for (const [key, value] of Object.entries(corsH)) {
		headers.set(key, value);
	}
	headers.set('Content-Type', 'text/plain');
	return new Response(body, { status, headers });
}

function handleCors(request: Request, env: Env): Response {
	return new Response(null, {
		status: 204,
		headers: getCorsHeaders(request, env)
	});
}

function getCorsHeaders(request: Request, env: Env): Record<string, string> {
	const origin = request.headers.get('Origin');
	const allowedStr = env.ALLOWED_DOMAINS || '';
	
	const corsHeaders: Record<string, string> = {
		'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
		'Access-Control-Allow-Headers': '*',
		'Access-Control-Expose-Headers': 'Content-Range, Content-Length, Accept-Ranges',
		'Access-Control-Max-Age': '86400'
	};

	if (origin) {
		const cleanOrigin = origin.replace(/^https?:\/\//, '').toLowerCase();
		let isAllowed = false;
		
		if (allowedStr === '*' || allowedStr === '') {
			isAllowed = true;
		} else {
			const allowed = allowedStr.split(',').map(d => d.trim().toLowerCase().replace(/^https?:\/\//, ''));
			isAllowed = allowed.some(d => cleanOrigin === d || cleanOrigin.endsWith('.' + d));
		}
		
		if (isAllowed) {
			corsHeaders['Access-Control-Allow-Origin'] = origin;
			corsHeaders['Access-Control-Allow-Credentials'] = 'true';
		}
	}

	return corsHeaders;
}

function base64UrlDecode(str: string): string {
	let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
	while (base64.length % 4) {
		base64 += '=';
	}
	return atob(base64);
}

function hexToUint8Array(hexString: string): Uint8Array {
	if (hexString.length % 2 !== 0) {
		throw new Error('Invalid hex string');
	}
	const arrayBuffer = new Uint8Array(hexString.length / 2);
	for (let i = 0; i < hexString.length; i += 2) {
		arrayBuffer[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
	}
	return arrayBuffer;
}

async function verifyHmac(message: string, signatureHex: string, secret: string): Promise<boolean> {
	try {
		const encoder = new TextEncoder();
		const keyData = encoder.encode(secret);
		const cryptoKey = await crypto.subtle.importKey(
			'raw',
			keyData,
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['verify', 'sign']
		);
		const msgBytes = encoder.encode(message);
		const sigBytes = hexToUint8Array(signatureHex);
		return await crypto.subtle.verify('HMAC', cryptoKey, sigBytes, msgBytes);
	} catch (e) {
		return false;
	}
}

function getCookie(request: Request, name: string): string | null {
	const cookieHeader = request.headers.get('Cookie');
	if (!cookieHeader) return null;
	
	const cookies = cookieHeader.split(';');
	for (const cookie of cookies) {
		const [key, val] = cookie.trim().split('=');
		if (key === name) {
			return decodeURIComponent(val);
		}
	}
	return null;
}

function generateFingerprint(request: Request): string {
	const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
	const ua = request.headers.get('User-Agent') || 'unknown';
	const country = request.headers.get('CF-IPCountry') || (request.cf?.country as string) || 'unknown';
	const asn = String(request.cf?.asn || 'unknown');
	
	let subnet = '';
	if (ip.includes(':')) {
		const parts = ip.split(':');
		subnet = parts.slice(0, 2).join(':');
	} else {
		const parts = ip.split('.');
		subnet = parts.slice(0, 2).join('.');
	}
	return `${subnet}|${country}|${asn}|${ua}`;
}