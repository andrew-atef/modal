export interface Env {
	VIDEO_KEYS: KVNamespace;
	BUCKET: R2Bucket;
	WAE: AnalyticsEngineDataset;
	ENVIRONMENT_SECRET: string;
	ALLOWED_DOMAINS: string;
}

interface AnalyticsEngineDataset {
	writeDataPoint(event?: {
		blobs?: (string | null)[];
		doubles?: (number | null)[];
		indexes?: (string | null)[];
	}): void;
}

const DIRECT_CDN = "https://cdm.devawi.tech/processed";
const PULSE_CDN = "https://pulse.devawi.tech/processed";

const encoder = new TextEncoder();

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);

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

		const path = url.pathname;
		const match = path.match(/^\/processed\/([^/]+)\/(.+)$/);
		if (!match) {
			return corsResponse('Not Found', 404, request, env);
		}

		const videoId = match[1];
		const relPath = match[2];

		const indexMatch = relPath.match(/(?:_|^|[^0-9])(\d+)\.(mp4|m4s|ts)$/);
		let segmentIndex = -1;
		if (indexMatch) {
			segmentIndex = parseInt(indexMatch[1], 10);
		}

		const isSegment = relPath.match(/\.(mp4|m4s|ts)$/);
		const isTargetSegment = segmentIndex === 0 || (segmentIndex > 0 && segmentIndex % 6 === 0);

		if (isSegment && !isTargetSegment) {
			return corsResponse('Forbidden: Segment must be fetched from Direct CDN', 403, request, env);
		}

		const rangeHeader = request.headers.get('Range');
		const r2Options: R2GetOptions = {};
		if (rangeHeader) {
			r2Options.range = rangeHeader;
		}

		const otpVal = url.searchParams.get('otp');
		let tokenVal = url.searchParams.get('token');

		// --- OTP (One-Time Password) Exchange Flow ---
		if (otpVal) {
			const otpKey = `otp:${otpVal}`;
			const otpPayloadStr = await env.VIDEO_KEYS.get(otpKey);
			if (!otpPayloadStr) {
				return corsResponse('Forbidden: Invalid or already used OTP', 403, request, env);
			}

			let otpPayload: any;
			try {
				otpPayload = JSON.parse(otpPayloadStr);
			} catch (e) {
				return corsResponse('Forbidden: Corrupted OTP payload structure', 403, request, env);
			}

			// Validate Expiration
			const nowSec = Math.floor(Date.now() / 1000);
			const expiry = otpPayload.expires_at || otpPayload.expires || otpPayload.exp;
			if (expiry && nowSec > expiry) {
				return corsResponse('Forbidden: OTP expired', 403, request, env);
			}

			// --- Web Security Validation ---
			if (isBrowser) {
				const referer = request.headers.get('Referer') || request.headers.get('Origin') || "";
				const whitelisthref = otpPayload.whitelisthref;
				if (whitelisthref) {
					try {
						const regex = new RegExp(whitelisthref, 'i');
						if (!regex.test(referer)) {
							return corsResponse('Forbidden: OTP referer domain not allowed', 403, request, env);
						}
					} catch(e) {
						if (!referer.toLowerCase().includes(whitelisthref.toLowerCase())) {
							return corsResponse('Forbidden: OTP referer domain not allowed', 403, request, env);
						}
					}
				} else {
					// Fallback to legacy allowed_domains check
					const allowedDomains = otpPayload.allowed_domains || otpPayload.domains;
					if (allowedDomains && allowedDomains.length > 0 && referer) {
						if (!isDomainAllowed(referer, allowedDomains)) {
							return corsResponse('Forbidden: OTP referer domain not allowed', 403, request, env);
						}
					}
				}
			}

			// --- Native Mobile Security Validation ---
			if (isNativeMobile) {
				const appId = request.headers.get('X-App-Id') || url.searchParams.get('app_id') || url.searchParams.get('appId') || "";
				const allowedAppId = otpPayload.app_id || "";
				const allowedPackages = otpPayload.allowed_packages || [];

				let matched = false;
				if (appId) {
					if (allowedAppId && appId === allowedAppId) {
						matched = true;
					} else if (allowedPackages && allowedPackages.includes(appId)) {
						matched = true;
					}
				}
				if ((allowedAppId || allowedPackages.length > 0) && !matched) {
					return corsResponse('Forbidden: Unauthorized Native App', 403, request, env);
				}
			}

			// --- Geo/IP Validation ---
			const clientIp = request.headers.get('CF-Connecting-IP');
			const clientCountry = (request.headers.get('CF-IPCountry') || (request.cf as any)?.country) as string | null;

			if (otpPayload.ipGeo) {
				if (!validateIpGeo(clientIp, clientCountry, otpPayload.ipGeo)) {
					return corsResponse('Forbidden: OTP geo or IP blocked', 403, request, env);
				}
			} else {
				// Fallback to legacy allowed countries & IPs checks
				const allowedCountries = otpPayload.allowed_countries || otpPayload.countries;
				if (allowedCountries && allowedCountries.length > 0 && clientCountry) {
					if (!allowedCountries.includes(clientCountry)) {
						return corsResponse('Forbidden: OTP country location not allowed', 403, request, env);
					}
				}
				const allowedIps = otpPayload.allowed_ips || otpPayload.ips;
				if (allowedIps && allowedIps.length > 0 && clientIp) {
					if (!allowedIps.includes(clientIp)) {
						return corsResponse('Forbidden: OTP IP address not allowed', 403, request, env);
					}
				}
			}

			// Fetch Dynamic Secret
			const tenantId = otpPayload.tenant_id || otpPayload.tenantId;
			const tenantSecretKey = `tenant:${tenantId}:secret`;
			let secret = await env.VIDEO_KEYS.get(tenantSecretKey);
			if (!secret) {
				secret = env.ENVIRONMENT_SECRET;
			}

			// Generate signed JWT session token (12 hours)
			const clientTls = (request.cf as any)?.tlsClientHello?.tlsFingerprint32 || (request.cf as any)?.tlsFingerprint32 || "";
			
			let annotateObj = null;
			if (otpPayload.annotate) {
				try {
					annotateObj = typeof otpPayload.annotate === 'string' ? JSON.parse(otpPayload.annotate) : otpPayload.annotate;
				} catch(e) {
					annotateObj = otpPayload.annotate;
				}
			}

			const jwtPayload = {
				video_id: videoId,
				tenant_id: tenantId,
				watermark_text: otpPayload.watermark_text || "",
				annotate: annotateObj,
				exp: nowSec + 12 * 3600,
				fingerprint: generateFingerprint(request),
				tlsFingerprint32: clientTls,
				jti: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2) + Date.now().toString(36)
			};

			tokenVal = await generateJwt(jwtPayload, secret);

			// Delete single-use OTP immediately after first-time exchange
			ctx.waitUntil(env.VIDEO_KEYS.delete(otpKey));
		}

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

		// --- Update Billing WAE Math for exactly 10-second segments ---
		if (isTargetSegment) {
			const segmentName = relPath.split('/').pop() || '';
			if (!segmentName.toLowerCase().includes('audio')) {
				let qualityName = 'unknown';
				const qualityMatch = segmentName.match(/^([a-zA-Z0-9_]+)_/);
				if (qualityMatch) {
					qualityName = qualityMatch[1];
				}

				if (env.WAE) {
					try {
						let billingDoubles = [60];
						if (segmentIndex === 0) {
							billingDoubles = [10]; 
						} else if (segmentIndex === 6) {
							billingDoubles = [54]; 
						}

						env.WAE.writeDataPoint({ 
							blobs: [videoId, payload.tenant_id, qualityName], 
							doubles: billingDoubles
						});
					} catch (aeError) {
						console.error('[Analytics] WAE write failed:', aeError);
					}
				}
			}
		}

		// --- إعادة كتابة المانيفست بالـ Edge Cache الآمن لمنع استنزاف نفقات الـ R2 Class B كلياً ---
		if (relPath.endsWith('.m3u8') || relPath.endsWith('.mpd')) {
			const cache = (caches as any).default;
			const rawCacheUrl = new URL(request.url);
			
			// --- تصحيح معماري حاسم (Cache Key Fix): تصفير محرك البحث الممرر لمنع تسريب التوكن وجعل الكاش موحداً لكافة الطلاب ---
			rawCacheUrl.search = ''; 
			rawCacheUrl.pathname = `/internal/raw/${videoId}/${relPath}`;
			const rawCacheKey = new Request(rawCacheUrl.toString(), { method: 'GET' });
			
			let rawText: string | null = null;
			const cachedResponse = await cache.match(rawCacheKey);
			
			if (cachedResponse) {
				rawText = await cachedResponse.text();
			} else {
				const r2Key = `processed/${videoId}/${relPath}`;
				const object = await env.BUCKET.get(r2Key);
				if (!object) return corsResponse('Not Found', 404, request, env);
				
				rawText = await object.text();
				
				const cacheResponse = new Response(rawText, {
					headers: { 'Cache-Control': 's-maxage=15' } 
				});
				ctx.waitUntil(cache.put(rawCacheKey, cacheResponse));
			}

			let text = rawText!;

			const pathParts = relPath.split('/');
			const dirPrefix = pathParts.length > 1 ? pathParts.slice(0, pathParts.length - 1).join('/') + '/' : '';

			const lines = text.split('\n');

			const rewriteUriInTag = (tagLine: string): string => {
				return tagLine.replace(/URI="([^"]+)"/g, (_full, uri) => {
					if (uri.includes('/keys/')) {
						return `URI="https://license.devawi.tech/keys/${videoId}?token=${tokenVal}"`;
					}
					if (uri.endsWith('.m3u8')) {
						const filename = uri.split('/').pop()!;
						return `URI="${PULSE_CDN}/${videoId}/${dirPrefix}${filename}?token=${tokenVal}"`;
					}
					return `URI="${DIRECT_CDN}/${videoId}/${dirPrefix}${uri}"`;
				});
			};

			const rewrittenLines = lines.map((line: string) => {
				const trimmed = line.trim();
				if (trimmed === '') return line;

				if (trimmed.startsWith('#')) {
					if (trimmed.startsWith('#EXT-X-KEY:') || trimmed.startsWith('#EXT-X-SESSION-KEY:')) {
						return line.replace(/URI="[^"]+"/g, `URI="https://license.devawi.tech/keys/${videoId}?token=${tokenVal}"`);
					}
					if (trimmed.includes('URI="')) {
						return rewriteUriInTag(line);
					}
					return line;
				}

				if (trimmed.endsWith('.m3u8') || trimmed.endsWith('.mpd')) {
					if (trimmed.includes('master')) return line;
					return `${PULSE_CDN}/${videoId}/${dirPrefix}${trimmed}?token=${tokenVal}`;
				}

				const idxMatch = trimmed.match(/(?:_|^|[^0-9])(\d+)\.(mp4|m4s|ts)$/);
				if (idxMatch) {
					const idx = parseInt(idxMatch[1], 10);
					if (idx === 0 || (idx > 0 && idx % 6 === 0)) {
						return `${PULSE_CDN}/${videoId}/${dirPrefix}${trimmed}?token=${tokenVal}`;
					}
				}

				return `${DIRECT_CDN}/${videoId}/${dirPrefix}${trimmed}`;
			});
			text = rewrittenLines.join('\n');

			const headers = new Headers();
			const corsH = getCorsHeaders(request, env);
			for (const [key, value] of Object.entries(corsH)) {
				headers.set(key, value);
			}
			headers.set('Content-Type', 'application/x-mpegURL');
			headers.set('Cache-Control', 'no-cache, no-store, must-revalidate');

			return new Response(text, { status: 200, headers });
		}

		return serveWithCache(relPath, videoId, env, ctx, r2Options, request, rangeHeader);
	}
};

async function serveWithCache(
	relPath: string,
	videoId: string,
	env: Env,
	ctx: ExecutionContext,
	r2Options: R2GetOptions,
	request: Request,
	rangeHeader: string | null
): Promise<Response> {
	const r2Key = `processed/${videoId}/${relPath}`;
	const cache = (caches as any).default;
	const cacheUrl = new URL(request.url);
	cacheUrl.search = ''; 
	const cacheKey = new Request(cacheUrl.toString(), { method: 'GET' });

	const isTs = relPath.endsWith('.ts');
	const useCache = request.method === 'GET' && (!rangeHeader || isTs) && (relPath.endsWith('.m4s') || relPath.endsWith('.mp4') || isTs);
	
	if (useCache) {
		let cachedResponse = await cache.match(cacheKey);
		if (cachedResponse) {
			const newHeaders = new Headers(cachedResponse.headers);
			const corsH = getCorsHeaders(request, env);
			for (const [key, value] of Object.entries(corsH)) {
				newHeaders.set(key, value);
			}
			return new Response(cachedResponse.body, {
				status: cachedResponse.status,
				headers: newHeaders
			});
		}
	}

	try {
		const object = await env.BUCKET.get(r2Key, r2Options);
		if (object === null) {
			return corsResponse('Not Found', 404, request, env);
		}

		const headers = new Headers();
		if (object.writeHttpMetadata) {
			object.writeHttpMetadata(headers);
		}

		const corsH = getCorsHeaders(request, env);
		for (const [key, value] of Object.entries(corsH)) {
			headers.set(key, value);
		}

		if (relPath.endsWith('.m4s')) {
			headers.set('Content-Type', 'video/iso.segment');
		} else if (relPath.endsWith('.mp4')) {
			headers.set('Content-Type', 'video/mp4');
		} else if (relPath.endsWith('.ts')) {
			headers.set('Content-Type', 'video/mp2t');
		} else if (relPath.endsWith('.m3u8')) {
			headers.set('Content-Type', 'application/x-mpegURL');
		}

		if (relPath.endsWith('.m4s') || relPath.endsWith('.mp4') || relPath.endsWith('.ts')) {
			headers.set('Cache-Control', 'public, max-age=31536000, immutable');
		} else {
			headers.set('Cache-Control', 'no-cache, no-store, must-revalidate');
		}

		if (request.method === 'HEAD') {
			return new Response(null, { headers });
		}

		const status = (rangeHeader && object.size !== 0) ? 206 : 200;
		const response = new Response(object.body, { status, headers });

		if (useCache && status === 200) {
			ctx.waitUntil(cache.put(cacheKey, response.clone()));
		}

		return response;

	} catch (error) {
		return corsResponse('Internal Server Error', 500, request, env);
	}
}

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

function base64UrlEncode(arr: Uint8Array): string {
	let binary = '';
	const len = arr.byteLength;
	for (let i = 0; i < len; i++) {
		binary += String.fromCharCode(arr[i]);
	}
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64UrlEncodeStr(str: string): string {
	return base64UrlEncode(encoder.encode(str));
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

async function generateJwt(payload: any, secret: string): Promise<string> {
	const header = { alg: "HS256", typ: "JWT" };
	const headerB64 = base64UrlEncodeStr(JSON.stringify(header));
	const payloadB64 = base64UrlEncodeStr(JSON.stringify(payload));
	const message = `${headerB64}.${payloadB64}`;
	
	const keyData = encoder.encode(secret);
	const cryptoKey = await crypto.subtle.importKey(
		'raw',
		keyData,
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign']
	);
	
	const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(message));
	const signatureB64 = base64UrlEncode(new Uint8Array(signature));
	return `${message}.${signatureB64}`;
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

function hexToUint8Array(hex: string): Uint8Array {
	if (hex.length % 2 !== 0) {
		throw new Error('Invalid hex string');
	}
	const arr = new Uint8Array(hex.length / 2);
	for (let i = 0; i < arr.length; i++) {
		arr[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
	}
	return arr;
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

function validateIpGeo(ip: string | null, country: string | null, ipGeo: any): boolean {
	if (!ipGeo || typeof ipGeo !== 'object') return true;

	const ipStr = ip || '';
	const countryStr = (country || '').toUpperCase();

	const allowList: string[] = Array.isArray(ipGeo.allow) ? ipGeo.allow : (typeof ipGeo.allow === 'string' ? [ipGeo.allow] : []);
	const blockList: string[] = Array.isArray(ipGeo.block) ? ipGeo.block : (typeof ipGeo.block === 'string' ? [ipGeo.block] : []);
	const exceptList: string[] = Array.isArray(ipGeo.except) ? ipGeo.except : (typeof ipGeo.except === 'string' ? [ipGeo.except] : []);

	const normalizedAllow = allowList.map(x => x.trim().toUpperCase());
	const normalizedBlock = blockList.map(x => x.trim().toUpperCase());
	const normalizedExcept = exceptList.map(x => x.trim().toUpperCase());

	const matches = (item: string) => {
		if (item === ipStr.toUpperCase()) return true;
		if (item === countryStr) return true;
		if (item.includes('/') && ipStr) {
			const [subnet] = item.split('/');
			const subnetParts = subnet.split('.');
			const ipParts = ipStr.split('.');
			if (subnetParts.length >= 3 && ipParts.length >= 3) {
				return subnetParts[0] === ipParts[0] && subnetParts[1] === ipParts[1] && subnetParts[2] === ipParts[2];
			}
		}
		return false;
	};

	const isExcepted = normalizedExcept.some(matches);

	if (normalizedBlock.length > 0 && !isExcepted) {
		if (normalizedBlock.some(matches)) {
			return false;
		}
	}

	if (normalizedAllow.length > 0) {
		if (isExcepted) return true;
		return normalizedAllow.some(matches);
	}

	return true;
}