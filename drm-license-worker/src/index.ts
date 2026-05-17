import { jwtVerify } from 'jose';

export interface Env {
	VIDEO_KEYS: KVNamespace;
	JWT_SECRET: string;
	ALLOWED_DOMAINS: string;
}

// ذاكرة مؤقتة للـ API Secrets الخاصة بالمستأجرين لتقليل قراءات KV
const tenantSecretCache = new Map<string, { secret: Uint8Array, expires: number }>();

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		const pathParts = url.pathname.split('/');
		
		// 1. Handle CORS Preflight
		if (request.method === 'OPTIONS') {
			return handleCors(request, env);
		}

		// 2. Validate Endpoint: /license/:video_id
		if (pathParts[1] !== 'license' || !pathParts[2]) {
			return new Response('Not Found', { status: 404 });
		}
		const videoId = pathParts[2];

		// Strengthen Origin/Referer Validation
		const origin = request.headers.get('Origin') || '';
		const referer = request.headers.get('Referer') || '';
		const allowedStr = env.ALLOWED_DOMAINS || '';
		
		if (allowedStr && allowedStr !== '*') {
			const allowedDomains = allowedStr.split(',').map(d => {
				let clean = d.trim().toLowerCase();
				clean = clean.replace(/^https?:\/\//, '');
				return clean.split('/')[0];
			});

			let requestHost = '';
			if (origin) {
				try { requestHost = new URL(origin).hostname.toLowerCase(); } catch { requestHost = origin.toLowerCase(); }
			} else if (referer) {
				try { requestHost = new URL(referer).hostname.toLowerCase(); } catch {}
			}

			if (!requestHost) {
				return new Response('Forbidden: Missing Origin/Referer headers', { status: 403 });
			}

			const isAllowed = allowedDomains.some(domain => {
				return requestHost === domain || requestHost.endsWith('.' + domain);
			});

			if (!isAllowed) {
				console.error(`Unauthorized domain access: ${requestHost}`);
				return new Response('Forbidden: Unauthorized Domain', { status: 403 });
			}
		}

		// 3. Security Hardening: User-Agent Check
		const ua = request.headers.get('User-Agent') || '';
		const blockedUAs = ['IDM', 'Aria2', 'Postman', 'curl', 'wget'];
		if (blockedUAs.some(b => ua.includes(b))) {
			return new Response('Forbidden: Tooling not allowed', { status: 403 });
		}

		// 4. Token Extraction
		let token = url.searchParams.get('token');
		if (!token) {
			const authHeader = request.headers.get('Authorization');
			if (authHeader?.startsWith('Bearer ')) {
				token = authHeader.substring(7);
			}
		}

		if (!token) {
			return new Response('Unauthorized: Missing Token', { status: 401 });
		}

		try {
			// 5. جلب بيانات المفاتيح والمالك من KV
			const kvKey = `video:${videoId}:keys`;
			console.log(`[KV] Fetching key: ${kvKey}`);
			const keyDataJson = await env.VIDEO_KEYS.get(kvKey);
			if (!keyDataJson) {
				return new Response('Not Found: License not generated yet', { status: 404 });
			}
			
			let keyData;
			try {
				keyData = JSON.parse(keyDataJson);
				if (typeof keyData === 'string') {
					keyData = JSON.parse(keyData); // Handle double-encoding just in case
				}
			} catch (parseError) {
				console.error(`[KV] JSON Parse Error for key ${kvKey}:`, parseError);
				return new Response('Internal Server Error: Corrupt KV Data', { status: 500 });
			}

			const ownerId = keyData.owner_id;

			if (!ownerId) {
				return new Response('Error: Missing Owner ID in metadata', { status: 500 });
			}

			// 6. جلب الـ API Secret الخاص بالمالك (مع التخزين المؤقت)
			let tenantSecret = tenantSecretCache.get(ownerId);
			const now = Date.now();

			if (!tenantSecret || now > tenantSecret.expires) {
				let secretStr = await env.VIDEO_KEYS.get('tenant:' + ownerId + ':secret');
				if (!secretStr) {
					return new Response('Unauthorized: Tenant secret not found', { status: 401 });
				}
				
				// Strip surrounding double quotes if present (common when storing raw values via Laravel JSON APIs)
				if (secretStr.startsWith('"') && secretStr.endsWith('"')) {
					secretStr = secretStr.slice(1, -1);
				}
				
				secretStr = secretStr.trim();
				console.log(`[DEBUG] KV Secret retrieved for owner ${ownerId}. Sanitized Length: ${secretStr.length}`);

				tenantSecret = {
					secret: new TextEncoder().encode(secretStr),
					expires: now + 60000 // كاش لمدة دقيقة واحدة
				};
				tenantSecretCache.set(ownerId, tenantSecret);
			}

			// 7. JWT Verification (Tenant-Specific)
			const { payload } = await jwtVerify(token, tenantSecret.secret);

			// Nonce Protection (JTI replay attack prevention)
			if (payload.jti) {
				const nonceKey = 'nonce:' + payload.jti;
				const usedNonce = await env.VIDEO_KEYS.get(nonceKey);
				if (usedNonce) {
					console.error(`Token replay attempt detected. JTI: ${payload.jti}`);
					return new Response('Forbidden: Token already used', { status: 403 });
				}
				// Save the nonce for 1 hour to prevent re-use
				await env.VIDEO_KEYS.put(nonceKey, '1', { expirationTtl: 3600 });
			}

			// 8. Security Check: Payload Video ID must match requested Video ID
			if (payload.video_id !== videoId) {
				return new Response('Forbidden: Token issued for different video', { status: 403 });
			}

			// Log the KID to verify against manifest
			console.log("[Worker] Issuing License for KID (Hex):", keyData.kid);

			// 10. Route Handling based on Accept header and Native Safari detection
			const acceptHeader = request.headers.get('Accept') || '';
			const wantJson = acceptHeader.includes('application/json');
			
			if (isNativeSafari(request) && !wantJson) {
				// HLS Binary Format (Raw 16-byte Binary) - Default for iOS Safari
				try {
					const binaryKey = hexToUint8Array(keyData.key);
					return new Response(binaryKey, {
						headers: {
							'Content-Type': 'application/octet-stream',
							...getCorsHeaders(request, env)
						}
					});
				} catch (e) {
					console.error('Binary Key Conversion Error:', e);
					return new Response('Internal Server Error: Invalid Key Format', { status: 500 });
				}
			} else {
				// ClearKey JSON Format - Default for Desktop / Non-Safari / JSON requested
				try {
					const responseData = {
						keys: [
							{
								kty: 'oct',
								k: hexToBase64Url(keyData.key),
								kid: hexToBase64Url(keyData.kid)
							}
						],
						type: 'temporary'
					};

					return new Response(JSON.stringify(responseData), {
						headers: {
							'Content-Type': 'application/json',
							...getCorsHeaders(request, env)
						}
					});
				} catch (e) {
					console.error('ClearKey JSON Conversion Error:', e);
					return new Response('Internal Server Error: Invalid Key Format', { status: 500 });
				}
			}

		} catch (e) {
			console.error('JWT Error:', e);
			return new Response('Unauthorized: Invalid Token', { status: 401 });
		}
	},
};

function getCorsHeaders(request: Request, env: Env) {
	const origin = request.headers.get('Origin');
	const allowedStr = env.ALLOWED_DOMAINS || '*';
	const allowed = allowedStr.split(',').map(d => d.trim().toLowerCase());
	
	const corsHeaders: Record<string, string> = {
		'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
		'Access-Control-Allow-Headers': 'Content-Type, Authorization',
		'Access-Control-Max-Age': '86400',
	};

	if (origin) {
		const cleanOrigin = origin.replace(/^https?:\/\//, '').toLowerCase();
		const isAllowed = allowed.includes('*') || allowed.some(d => {
			const cleanD = d.replace(/^https?:\/\//, '');
			return cleanOrigin === cleanD || cleanOrigin.endsWith('.' + cleanD);
		});
		
		if (isAllowed) {
			corsHeaders['Access-Control-Allow-Origin'] = origin;
		}
	}

	return corsHeaders;
}

function handleCors(request: Request, env: Env) {
	return new Response(null, {
		status: 204,
		headers: getCorsHeaders(request, env)
	});
}

// Helper: Hex to Uint8Array (Binary)
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

// Helper: Hex to Base64URL
function hexToBase64Url(hex: string): string {
	const bytes = new Uint8Array(hex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
	const base64 = btoa(String.fromCharCode(...bytes));
	return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Helper: Detect native Safari on iOS (iPhone/iPad) or macOS (excluding Chrome/Firefox/Edge on macOS)
function isNativeSafari(request: Request): boolean {
	const ua = request.headers.get('User-Agent') || '';
	const isApple = /iPhone|iPad|Macintosh/i.test(ua);
	const isSafari = /Safari/i.test(ua) && !/Chrome|CriOS|Firefox|FxiOS|Edg|OPR/i.test(ua);
	return isApple && isSafari;
}
