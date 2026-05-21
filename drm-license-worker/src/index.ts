export interface Env {
	VIDEO_KEYS: KVNamespace;
	BUCKET: R2Bucket;
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

const encoder = new TextEncoder();

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		
		// --- Serverless Edge OTP Generation API ---
		const otpRouteMatch = url.pathname.match(/^\/api\/videos\/([^/]+)\/otp$/);
		if (otpRouteMatch) {
			const videoId = otpRouteMatch[1];

			if (request.method === 'OPTIONS') {
				const origin = request.headers.get('Origin');
				const headers = new Headers({
					'Access-Control-Allow-Origin': origin || '*',
					'Access-Control-Allow-Methods': 'POST, OPTIONS',
					'Access-Control-Allow-Headers': 'Content-Type, Authorization',
					'Access-Control-Expose-Headers': '*',
					'Access-Control-Max-Age': '86400',
					'Access-Control-Allow-Credentials': 'true'
				});
				return new Response(null, { status: 204, headers });
			}

			if (request.method !== 'POST') {
				return corsResponse('Method Not Allowed', 405, request, env);
			}

			// Dynamic Edge Authentication
			const authHeader = request.headers.get('Authorization');
			if (!authHeader || !authHeader.startsWith('Apisecret ')) {
				return corsResponse('Unauthorized: Missing or invalid Authorization header', 401, request, env);
			}
			const extractedSecret = authHeader.substring('Apisecret '.length).trim();
			
			const tenantId = await env.VIDEO_KEYS.get(`secret:${extractedSecret}`);
			if (!tenantId || tenantId.trim() === '') {
				return corsResponse('Unauthorized: Invalid API secret key', 401, request, env);
			}

			// Strict Cryptographic Ownership Check (Strong Consistency)
			const r2Key = `processed/${videoId}/keys.json`;
			const r2Object = await env.BUCKET.get(r2Key);
			if (!r2Object) {
				return corsResponse('Not Found: Video keys missing', 404, request, env);
			}

			let keyData: any;
			try {
				const text = await r2Object.text();
				keyData = JSON.parse(text);
				if (typeof keyData === 'string') {
					keyData = JSON.parse(keyData);
				}
			} catch (e) {
				return corsResponse('Internal Server Error: Failed to parse video metadata', 500, request, env);
			}

			if (keyData.owner_id !== tenantId) {
				return corsResponse('Forbidden: Video library isolation breach', 403, request, env);
			}

			let body: any = {};
			try {
				body = await request.json();
			} catch (e) {
				// Body is empty or malformed
			}

			const ttl = typeof body.ttl === 'number' ? body.ttl : (typeof body.expirationTtl === 'number' ? body.expirationTtl : 300);
			const userId = typeof body.userId === 'string' ? body.userId : "";
			const annotateVal = body.annotate;
			const whitelisthref = typeof body.whitelisthref === 'string' ? body.whitelisthref : "";
			const ipGeo = body.ipGeo || null;
			const appId = body.app_id || "";

			let annotateJsonString = "";
			let watermarkText = "";

			if (annotateVal) {
				if (typeof annotateVal === 'object') {
					annotateJsonString = JSON.stringify(annotateVal);
				} else {
					annotateJsonString = String(annotateVal);
				}
				
				// Try to extract dynamic text from annotation object/array
				try {
					const parsed = typeof annotateVal === 'string' ? JSON.parse(annotateVal) : annotateVal;
					if (Array.isArray(parsed)) {
						const textObj = parsed.find((x: any) => x && typeof x === 'object' && x.text);
						if (textObj) {
							watermarkText = String(textObj.text);
						}
					} else if (parsed && typeof parsed === 'object') {
						watermarkText = String(parsed.text || parsed.watermark_text || parsed.watermarkText || "");
					} else {
						watermarkText = String(parsed);
					}
				} catch (e) {
					watermarkText = String(annotateVal);
				}
			}

			if (!watermarkText && userId) {
				watermarkText = userId;
			}

			if (watermarkText && userId) {
				watermarkText = watermarkText.replace(/{userId}/g, userId);
			}

			const unixTimestampAfterTtl = Math.floor(Date.now() / 1000) + ttl;
			const otpId = crypto.randomUUID();

			const otpPayload = {
				video_id: videoId,
				tenant_id: tenantId,
				watermark_text: watermarkText,
				annotate: annotateJsonString,
				whitelisthref: whitelisthref,
				ipGeo: ipGeo,
				app_id: appId,
				// Backwards compatibility support:
				allowed_domains: body.allowed_domains || (whitelisthref ? [whitelisthref] : []),
				allowed_packages: body.allowed_packages || (appId ? [appId] : []),
				expires_at: unixTimestampAfterTtl
			};

			// Write OTP to KV with specified TTL
			await env.VIDEO_KEYS.put(`otp:${otpId}`, JSON.stringify(otpPayload), { expirationTtl: ttl });

			// Return VdoCipher-style JSON response with base64url encoded metadata
			const playbackInfoObj = {
				video_id: videoId,
				videoId: videoId
			};
			const playbackInfoBase64 = btoa(JSON.stringify(playbackInfoObj))
				.replace(/\+/g, '-')
				.replace(/\//g, '_')
				.replace(/=/g, '');

			return corsJsonResponse({
				otp: otpId,
				playbackInfo: playbackInfoBase64
			}, 200, request, env);
		}

		const pathParts = url.pathname.split('/');
		
		const userAgent = request.headers.get('User-Agent') || '';
		if (!userAgent || userAgent.trim() === '') {
			return corsResponse('Forbidden: Missing User-Agent header', 403, request, env);
		}
		
		const isNativeMobile = /AppleCoreMedia|ExoPlayer|Dalvik|okhttp|flutter|uwsgi/i.test(userAgent);
		const isBrowser = !isNativeMobile;

		if (isBrowser) {
			if (/idman|download|grabber|phantom|headless|curl|wget|libcurl|python|requests/i.test(userAgent)) {
				return corsResponse('Forbidden: Automated requests not allowed', 403, request, env);
			}
		}

		if (request.method === 'OPTIONS') {
			if (isNativeMobile) {
				return new Response(null, { status: 204 });
			}
			const tokenVal = url.searchParams.get('token');
			if (!tokenVal) {
				return corsResponse('Forbidden: Missing token in OPTIONS', 403, request, env);
			}
			try {
				const payload = decodeTokenPayload(tokenVal);
				
				const origin = request.headers.get('Origin');
				let isPlatformSelf = false;
				if (origin) {
					try {
						const originUrl = new URL(origin);
						if (originUrl.hostname === 'pulse.devawi.tech' || originUrl.hostname === 'license.devawi.tech') {
							isPlatformSelf = true;
						}
					} catch(e) {}
				}

				if (!isPlatformSelf) {
					const tenantDomainsStr = await env.VIDEO_KEYS.get(`tenant:${payload.tenant_id}:domains`) || '';
					let allowedDomains: string[] = [];
					if (tenantDomainsStr.trim().startsWith('[')) {
						allowedDomains = JSON.parse(tenantDomainsStr);
					} else {
						allowedDomains = tenantDomainsStr.split(',').map(d => d.trim()).filter(Boolean);
					}
					
					if (!origin || !isDomainAllowed(origin, allowedDomains)) {
						return corsResponse('Forbidden: CORS Origin not allowed', 403, request, env);
					}
				}
				
				const headers = new Headers({
					'Access-Control-Allow-Origin': origin || '*',
					'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
					'Access-Control-Allow-Headers': '*',
					'Access-Control-Expose-Headers': 'Content-Range, Content-Length, Accept-Ranges',
					'Access-Control-Max-Age': '86400',
					'Access-Control-Allow-Credentials': 'true'
				});
				return new Response(null, { status: 204, headers });
			} catch (e) {
				return corsResponse('Forbidden: Invalid token in OPTIONS', 403, request, env);
			}
		}

		// حظر البث في حال عدم تهيئة المفتاح السري بأمان
		if (!env.ENVIRONMENT_SECRET || env.ENVIRONMENT_SECRET.length < 32) {
			console.error("[CRITICAL] ENVIRONMENT_SECRET is missing or insecure!");
			return corsResponse('Internal Server Error: Secure environment bypass blocked', 500, request, env);
		}

		if (pathParts[1] !== 'keys' || !pathParts[2]) {
			return corsResponse('Not Found', 404, request, env);
		}
		const videoId = pathParts[2];

		const tokenVal = url.searchParams.get('token');
		if (!tokenVal) {
			return corsResponse('Forbidden: Missing authentication token', 403, request, env);
		}

		// --- Dual-Mode Token Verification Gate ---
		const parts = tokenVal.split('.');
		let payload: any = null;
		let isValidToken = false;

		if (parts.length === 3) {
			// Standard 3-part JWT: header.payload.signature
			const [headerB64, payloadB64, signatureB64] = parts;
			try {
				payload = JSON.parse(base64UrlDecode(payloadB64));
				const tenantSecretKey = `tenant:${payload.tenant_id}:secret`;
				let secret = await env.VIDEO_KEYS.get(tenantSecretKey);
				if (!secret) {
					secret = env.ENVIRONMENT_SECRET;
				}
				
				const message = `${headerB64}.${payloadB64}`;
				const sigBytes = base64UrlDecodeToBytes(signatureB64);
				const keyData = encoder.encode(secret);
				const cryptoKey = await crypto.subtle.importKey(
					'raw',
					keyData,
					{ name: 'HMAC', hash: 'SHA-256' },
					false,
					['verify']
				);
				const msgBytes = encoder.encode(message);
				isValidToken = await crypto.subtle.verify('HMAC', cryptoKey, sigBytes as any, msgBytes as any);
			} catch (e) {
				isValidToken = false;
			}
		} else if (parts.length === 2) {
			// Legacy 2-part token: payloadB64.signatureHex
			const [payloadB64, signatureHex] = parts;
			try {
				payload = JSON.parse(base64UrlDecode(payloadB64));
				const tenantSecretKey = `tenant:${payload.tenant_id}:secret`;
				let secret = await env.VIDEO_KEYS.get(tenantSecretKey);
				if (!secret) {
					secret = env.ENVIRONMENT_SECRET;
				}
				isValidToken = await verifyHmac(payloadB64, signatureHex, secret);
			} catch (e) {
				isValidToken = false;
			}
		} else {
			return corsResponse('Forbidden: Invalid token format', 403, request, env);
		}

		if (!isValidToken || !payload) {
			return corsResponse('Forbidden: Tampered or invalid token signature', 403, request, env);
		}

		// Edge-Level Billing Suspension Check
		const isSuspended = await env.VIDEO_KEYS.get(`tenant:${payload.tenant_id}:suspended`);
		if (isSuspended === "true") {
			return corsResponse('Forbidden: Tenant account suspended', 403, request, env);
		}

		if (isBrowser) {
			const referer = request.headers.get('Referer');
			
			// --- الاستثناء الذكي للمنصة (Platform Self-Allowance) ---
			// إذا كان الطلب قادماً من مشغلنا الداخلي المعزول، نسمح له بالعبور فوراً ثقة بالـ Shadow DOM والتوكن
			let isPlatformSelf = false;
			if (referer) {
				try {
					const refUrl = new URL(referer);
					if (refUrl.hostname === 'pulse.devawi.tech' || refUrl.hostname === 'license.devawi.tech') {
						isPlatformSelf = true;
					}
				} catch(e) {}
			}

			if (!isPlatformSelf) {
				const tenantDomainsStr = await env.VIDEO_KEYS.get(`tenant:${payload.tenant_id}:domains`) || '';
				let allowedDomains: string[] = [];
				if (tenantDomainsStr.trim().startsWith('[')) {
					try {
						allowedDomains = JSON.parse(tenantDomainsStr);
					} catch(e) {}
				} else {
					allowedDomains = tenantDomainsStr.split(',').map(d => d.trim()).filter(Boolean);
				}
				
				const origin = request.headers.get('Origin');
				if (origin && !isDomainAllowed(origin, allowedDomains)) {
					return corsResponse('Forbidden: CORS Origin not allowed', 403, request, env);
				}
				
				if (!referer || !isDomainAllowed(referer, allowedDomains)) {
					return corsResponse('Forbidden: Referer not allowed', 403, request, env);
				}
			}
		} else if (isNativeMobile) {
			const appId = request.headers.get('X-App-Id');
			if (!appId) {
				return corsResponse('Forbidden: Unauthorized Native App (Missing X-App-Id)', 403, request, env);
			}
			
			const packagesStr = await env.VIDEO_KEYS.get(`tenant:${payload.tenant_id}:packages`) || '[]';
			let allowedPackages: string[] = [];
			try {
				allowedPackages = JSON.parse(packagesStr);
			} catch (e) {
				allowedPackages = packagesStr.split(',').map(p => p.trim()).filter(Boolean);
			}
			
			if (!allowedPackages.includes(appId)) {
				return corsResponse('Forbidden: Unauthorized Native App', 403, request, env);
			}
		}

		// التحقق من استخدام التوكن لمرة واحدة لطلب المفتاح لمنع الـ Replay Attack
		if (payload.jti) {
			const existingNonce = await env.VIDEO_KEYS.get(`nonce:${payload.jti}`);
			if (existingNonce) {
				return corsResponse('Forbidden: Token already used / Replay Attack Detected', 403, request, env);
			}
			ctx.waitUntil(env.VIDEO_KEYS.put(`nonce:${payload.jti}`, '1', { expirationTtl: 300 }));
		}

		if (payload.exp && Date.now() / 1000 > payload.exp) {
			return corsResponse('Forbidden: Session token expired', 403, request, env);
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
			// جلب المفتاح التشفيري من R2 مباشرة لضمان الثبات الفوري للبيانات (Strong Consistency) وبدون تكاليف KV
			const r2Key = `processed/${videoId}/keys.json`;
			const object = await env.BUCKET.get(r2Key);
			if (!object) return corsResponse('Not Found: Key file missing', 404, request, env);
			
			const keyDataJson = await object.text();
			
			let keyData;
			try {
				keyData = JSON.parse(keyDataJson);
				if (typeof keyData === 'string') {
					keyData = JSON.parse(keyData);
				}
			} catch (parseError) {
				return corsResponse('Internal Server Error: Corrupt Key Data', 500, request, env);
			}

			// Cryptographic Library Isolation
			if (keyData.owner_id !== payload.tenant_id) {
				return corsResponse('Forbidden: Library isolation breach', 403, request, env);
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

			const headers = new Headers();
			const corsH = getCorsHeaders(request, env);
			for (const [k, v] of Object.entries(corsH)) {
				headers.set(k, v);
			}
			headers.set('Cache-Control', 'private, no-store');

			const binaryKey = hexToUint8Array(keyData.key);
			headers.set('Content-Type', 'application/octet-stream');
			return new Response(binaryKey as any, { status: 200, headers });

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

function corsJsonResponse(data: any, status: number, request: Request, env: Env): Response {
	const headers = new Headers();
	const corsH = getCorsHeaders(request, env);
	for (const [key, value] of Object.entries(corsH)) {
		headers.set(key, value);
	}
	headers.set('Content-Type', 'application/json');
	return new Response(JSON.stringify(data), { status, headers });
}

function handleCors(request: Request, env: Env): Response {
	return new Response(null, {
		status: 204,
		headers: getCorsHeaders(request, env)
	});
}

function getCorsHeaders(request: Request, env: Env): Record<string, string> {
	const origin = request.headers.get('Origin');
	const corsHeaders: Record<string, string> = {
		'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
		'Access-Control-Allow-Headers': '*',
		'Access-Control-Expose-Headers': 'Content-Range, Content-Length, Accept-Ranges',
		'Access-Control-Max-Age': '86400'
	};

	if (origin) {
		corsHeaders['Access-Control-Allow-Origin'] = origin;
		corsHeaders['Access-Control-Allow-Credentials'] = 'true';
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

function base64UrlDecodeToBytes(str: string): Uint8Array {
	let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
	while (base64.length % 4) {
		base64 += '=';
	}
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

function decodeTokenPayload(token: string): any {
	const parts = token.split('.');
	if (parts.length === 3) {
		return JSON.parse(base64UrlDecode(parts[1]));
	} else if (parts.length === 2) {
		return JSON.parse(base64UrlDecode(parts[0]));
	}
	throw new Error('Invalid token structure');
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
		return await crypto.subtle.verify('HMAC', cryptoKey, sigBytes as any, msgBytes as any);
	} catch (e) {
		return false;
	}
}

function generateFingerprint(request: Request): string {
	const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
	const rawUa = request.headers.get('User-Agent') || 'unknown';
	const ua = rawUa.toLowerCase().replace(/\s+/g, '');
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

function isDomainAllowed(domainOrUrl: string | null, allowedDomains: string[]): boolean {
	if (!domainOrUrl) return false;
	let clean = domainOrUrl.replace(/^https?:\/\//, '').toLowerCase();
	clean = clean.split('/')[0].split(':')[0];
	return allowedDomains.some(d => {
		const cleanD = d.replace(/^https?:\/\//, '').toLowerCase().split('/')[0].split(':')[0];
		return clean === cleanD || clean.endsWith('.' + cleanD);
	});
}