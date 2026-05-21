const fs = require('fs');

function fixWorker(path) {
    let content = fs.readFileSync(path, 'utf8');
    
    content = content.replace(/let payload: \{ video_id: string; tenant_id: string; exp: number; fingerprint: string; jti: string \};/g, 'let payload: { video_id: string; tenant_id: string; exp: number; fingerprint: string; tlsFingerprint32?: string; jti: string };');
    
    content = content.replace(/payload = JSON\.parse\(base64UrlDecode\(payloadB64\)\);/g, 'payload = JSON.parse(base64UrlDecode(payloadB64 as string));');
    content = content.replace(/const isValidHmac = await verifyHmac\(payloadB64, signatureHex, secret\);/g, 'const isValidHmac = await verifyHmac(payloadB64 as string, signatureHex as string, secret as string);');
    
    content = content.replace(/crypto\.subtle\.verify\('HMAC', cryptoKey, sigBytes, msgBytes\)/g, "crypto.subtle.verify('HMAC', cryptoKey, sigBytes as any, msgBytes as any)");
    
    content = content.replace(/return new Response\(binaryKey, \{ status: 200, headers \}\);/g, "return new Response(binaryKey as any, { status: 200, headers });");
    
    fs.writeFileSync(path, content);
}

fixWorker('c:/Users/Andrew Atef/Downloads/freevid/modal/drm-license-worker/src/index.ts');
fixWorker('c:/Users/Andrew Atef/Downloads/freevid/modal/video-bandwidth-worker/src/index.ts');
