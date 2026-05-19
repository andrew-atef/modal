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

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);

		if (request.method === 'OPTIONS') {
			return handleCors(request, env);
		}

		const path = url.pathname;
		const match = path.match(/^\/processed\/([^/]+)\/(.+)$/);
		if (!match) {
			return corsResponse('Not Found', 404, request, env);
		}

		const videoId = match[1];
		const relPath = match[2];

		// تصحيح الـ Regex لمطابقة أرقام القطع المباشرة (مثل 0.ts) أو المدعومة بشرطة سفلية
		const indexMatch = relPath.match(/(?:_|^|[^0-9])(\d+)\.(mp4|m4s|ts)$/);
		let segmentIndex = -1;
		if (indexMatch) {
			segmentIndex = parseInt(indexMatch[1], 10);
		}

		const isSegment = relPath.match(/\.(mp4|m4s|ts)$/);
		// Pulse Billing: استهداف كل سادس قطعة (تمثل دقيقة تشغيل في قطع الـ 10 ثوان أو 36 ثانية لقطع الـ 6 ثوان)
		const isTargetSegment = segmentIndex >= 0 && segmentIndex % 6 === 0;

		if (isSegment && !isTargetSegment) {
			return corsResponse('Forbidden: Segment must be fetched from Direct CDN', 403, request, env);
		}

		const rangeHeader = request.headers.get('Range');
		const r2Options: R2GetOptions = {};
		if (rangeHeader) {
			r2Options.range = rangeHeader;
		}

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

		let payload: { video_id: string; tenant_id: string; exp: number; fingerprint: string };
		try {
			payload = JSON.parse(base64UrlDecode(payloadB64));
		} catch (e) {
			return corsResponse('Forbidden: Invalid payload encoding', 403, request, env);
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
						env.WAE.writeDataPoint({ 
							blobs: [videoId, payload.tenant_id, qualityName], 
							doubles: [36] // 6 قطع * 6 ثوان لكل قطعة = 36 ثانية تشغيل حقيقية
						});
					} catch (aeError) {
						console.error('[Analytics] AE write failed:', aeError);
					}
				}
			}
		}

		// --- منطق إعادة الكتابة الذكي والآمن للمانيفست ---
		if (relPath.endsWith('.m3u8') || relPath.endsWith('.mpd')) {
			const r2Key = `processed/${videoId}/${relPath}`;
			const object = await env.BUCKET.get(r2Key);
			if (!object) return corsResponse('Not Found', 404, request, env);

			let text = await object.text();

			// تم تعديل التعليق هنا من # إلى // لحل المشكلة برمجياً
			// استخراج بادئة المجلد ديناميكياً (مثل 720p/ أو 480p/ أو فارغ للماستر) للحفاظ على مسار الملفات المرفوعة في R2
			const pathParts = relPath.split('/');
			const dirPrefix = pathParts.length > 1 ? pathParts.slice(0, pathParts.length - 1).join('/') + '/' : '';

			const lines = text.split('\n');

			// دالة مساعدة لإعادة بناء الروابط بشكل يحافظ على المجلد والجودة
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

			const rewrittenLines = lines.map(line => {
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

				// التحقق من رقم الـ index للقطعة لإخضاعها للـ Billing أو تحويلها للـ Direct CDN مباشرة
				const idxMatch = trimmed.match(/(?:_|^|[^0-9])(\d+)\.(mp4|m4s|ts)$/);
				if (idxMatch) {
					const idx = parseInt(idxMatch[1], 10);
					if (idx >= 0 && idx % 6 === 0) {
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
	const cache = caches.default;
	const cacheUrl = new URL(request.url);
	cacheUrl.search = ''; 
	const cacheKey = new Request(cacheUrl.toString(), { method: 'GET' });

	const useCache = request.method === 'GET' && !rangeHeader && (relPath.endsWith('.m4s') || relPath.endsWith('.mp4') || relPath.endsWith('.ts'));
	
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
		const encoder = new TextEncoder();
		const keyData = encoder.encode(secret);
		const cryptoKey = await crypto.subtle.importKey(
			'raw',
			keyData,
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['verify', 'sign']
		);
		// التصحيح الحاسم هنا: يجب تشفير الرسالة (message) وليس السر (secret)
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