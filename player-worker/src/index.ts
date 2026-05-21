export interface Env {
	VIDEO_KEYS: KVNamespace;
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		
		// Serve player page
		if (url.pathname !== '/player' && url.pathname !== '/player/') {
			return new Response('Not Found', { status: 404 });
		}

		if (request.method !== 'GET' && request.method !== 'HEAD') {
			return new Response('Method Not Allowed', { status: 405 });
		}

		const otp = url.searchParams.get('otp');
		const playbackInfo = url.searchParams.get('playbackInfo');

		if (!otp || !playbackInfo) {
			return new Response('Bad Request: Missing otp or playbackInfo parameter', { status: 400 });
		}

		// --- فحص الـ Referer الأب عند البوابة الأولى للـ Iframe ---
		const otpDataStr = await env.VIDEO_KEYS.get(`otp:${otp}`);
		if (!otpDataStr) {
			return new Response('Forbidden: Expired or Invalid OTP session', { status: 403 });
		}

		let otpPayload: any;
		try {
			otpPayload = JSON.parse(otpDataStr);
		} catch (e) {
			return new Response('Internal Server Error', { status: 500 });
		}

		const referer = request.headers.get('Referer');
		const whitelisthref = otpPayload.whitelisthref;
		const allowedDomains: string[] = otpPayload.allowed_domains || otpPayload.domains || [];

		// تحقق صارم من الـ Referer الأب الحقيقي (موقع المدرس) لمنع سرقة الـ iframe كلياً
		if (whitelisthref) {
			if (!referer) {
				return new Response('Forbidden: Referer not allowed on this player channel', { status: 403 });
			}
			try {
				const regex = new RegExp(whitelisthref, 'i');
				if (!regex.test(referer)) {
					return new Response('Forbidden: Referer not allowed on this player channel', { status: 403 });
				}
			} catch(e) {
				if (!referer.toLowerCase().includes(whitelisthref.toLowerCase())) {
					return new Response('Forbidden: Referer not allowed on this player channel', { status: 403 });
				}
			}
		} else if (allowedDomains.length > 0) {
			if (!referer || !isDomainAllowed(referer, allowedDomains)) {
				return new Response('Forbidden: Referer not allowed on this player channel', { status: 403 });
			}
		}

		// Robust video ID extraction from playbackInfo
		let videoId = playbackInfo;
		try {
			let decoded = '';
			const base64 = playbackInfo.replace(/-/g, '+').replace(/_/g, '/');
			try {
				decoded = atob(base64);
			} catch (e) {
				decoded = atob(playbackInfo);
			}
			const parsed = JSON.parse(decoded);
			videoId = parsed.video_id || parsed.videoId || videoId;
		} catch (e) {
			// Fallback: use playbackInfo as the raw videoId
		}

		const html = getPlayerHtml(videoId, otp, playbackInfo);

		return new Response(html, {
			headers: {
				'Content-Type': 'text/html; charset=utf-8',
				'Cache-Control': 'no-cache, no-store, must-revalidate',
				'Access-Control-Allow-Origin': '*'
			}
		});
	}
};

function getPlayerHtml(videoId: string, otp: string, playbackInfo: string): string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Player</title>
    
    <!-- Shaka Player CDN -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/shaka-player/4.3.5/shaka-player.compiled.js"></script>
    
    <!-- Google Fonts Inter -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    
    <style>
        html, body {
            margin: 0;
            padding: 0;
            width: 100%;
            height: 100%;
            overflow: hidden;
            background: #000;
            font-family: 'Inter', sans-serif;
        }
        #player-container-outer {
            width: 100%;
            height: 100%;
            background: #000;
            position: relative;
        }
        .loading-overlay {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: #080d16;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 16px;
            z-index: 10;
            transition: opacity 0.5s ease;
        }
        .spinner {
            width: 48px;
            height: 48px;
            border: 3px solid rgba(59, 130, 246, 0.1);
            border-top-color: #3b82f6;
            border-radius: 50%;
            animation: spin 1s infinite linear;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .loading-text {
            font-size: 14px;
            color: #9ca3af;
            font-weight: 500;
            letter-spacing: 0.5px;
        }
    </style>
</head>
<body>
    <div id="player-container-outer">
        <div class="loading-overlay" id="loadingOverlay">
            <div class="spinner"></div>
            <div class="loading-text">Establishing Secure Session...</div>
        </div>
    </div>

    <script>
        // حظر قائمة الضغط الأيمن (Context Menu) تماماً على مستوى المشغل والصفحة لمنع Inspect Element
        document.addEventListener('contextmenu', (e) => e.preventDefault());

        // حظر اختصارات لوحة المفاتيح لاستكشاف الكود في حال تركيز الـ Focus على المشغل
        window.addEventListener('keydown', (e) => {
            if (e.key === 'F12' || 
                (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'i' || e.key === 'C' || e.key === 'c' || e.key === 'J' || e.key === 'j')) || 
                (e.ctrlKey && (e.key === 'U' || e.key === 'u'))
            ) {
                e.preventDefault();
            }
        });

        document.addEventListener('DOMContentLoaded', () => {
            const videoId = "${videoId}";
            const otp = "${otp}";
            const manifestUri = "https://pulse.devawi.tech/processed/" + videoId + "/master.m3u8?otp=" + otp;
            let watermarkText = '';
            
            const outerContainer = document.getElementById('player-container-outer');
            const shadowRoot = outerContainer.attachShadow({ mode: 'closed' });
            
            const style = document.createElement('style');
            style.textContent = \`
                .player-wrapper {
                    position: relative;
                    width: 100%;
                    height: 100%;
                    background: #000;
                    overflow: hidden;
                }
                video {
                    width: 100%;
                    height: 100%;
                    object-fit: contain;
                    outline: none;
                }
                canvas {
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100% !important;
                    height: 100% !important;
                    pointer-events: none;
                    z-index: 2147483647;
                    mix-blend-mode: difference; /* Force the watermark to dynamically invert and blend its colors based on the underlying video frame pixels */
                }
                .tamper-overlay {
                    position: absolute;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    background: #0b0f19;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 24px;
                    z-index: 2147483647;
                }
                .tamper-content {
                    background: rgba(239, 68, 68, 0.1);
                    border: 1px solid rgba(239, 68, 68, 0.3);
                    border-radius: 16px;
                    padding: 32px;
                    text-align: center;
                    max-width: 480px;
                    box-shadow: 0 10px 30px rgba(239, 68, 68, 0.15);
                }
                .tamper-title {
                    color: #f87171;
                    font-size: 18px;
                    font-weight: 700;
                    margin-bottom: 8px;
                    font-family: 'Inter', sans-serif;
                }
                .tamper-desc {
                    color: #9ca3af;
                    font-size: 13px;
                    line-height: 1.6;
                    font-family: 'Inter', sans-serif;
                }
            \`;
            shadowRoot.appendChild(style);

            const wrapper = document.createElement('div');
            wrapper.className = 'player-wrapper';
            
            const video = document.createElement('video');
            video.controls = true;
            video.autoplay = true;
            video.setAttribute('playsinline', 'true');
            video.setAttribute('controlslist', 'nodownload nofullscreen noremoteplayback');
            
            const canvas = document.createElement('canvas');
            
            wrapper.appendChild(video);
            wrapper.appendChild(canvas);
            shadowRoot.appendChild(wrapper);

            // منع قائمة الـ contextmenu للضغط الأيمن بداخل الـ Shadow DOM لزيادة الأمان
            wrapper.addEventListener('contextmenu', (e) => e.preventDefault());

            shaka.polyfill.installAll();
            if (!shaka.Player.isBrowserSupported()) {
                console.error('Browser not supported!');
                return;
            }

            const player = new shaka.Player(video);
            
            player.getNetworkingEngine().registerRequestFilter((type, request) => {
                const url = request.uris[0];
                const tokenMatch = url.match(/[?&]token=([^&]+)/);
                if (tokenMatch) {
                    const token = tokenMatch[1];
                    try {
                        const parts = token.split('.');
                        if (parts.length === 3) {
                            const payloadB64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
                            const payload = JSON.parse(atob(payloadB64));
                            if (payload && payload.watermark_text) {
                                watermarkText = payload.watermark_text;
                            }
                        }
                    } catch (e) {}
                }
            });

            player.load(manifestUri).then(() => {
                const loader = document.getElementById('loadingOverlay');
                if (loader) loader.style.opacity = '0';
                setTimeout(() => loader && loader.remove(), 500);
            }).catch((e) => {
                const loaderText = document.querySelector('.loading-text');
                if (loaderText) {
                    loaderText.textContent = "Authorization Failed. OTP expired.";
                    loaderText.style.color = "#f87171";
                }
                const spinner = document.querySelector('.spinner');
                if (spinner) {
                    spinner.style.borderTopColor = "#ef4444";
                    spinner.style.animationPlayState = "paused";
                }
            });

            const ctx = canvas.getContext('2d');
            let x = 50;
            let y = 100;
            let dx = 1.0;
            let dy = 0.6;

            function renderWatermark() {
                if (!canvas || !canvas.parentNode) return;
                
                if (canvas.width !== canvas.clientWidth || canvas.height !== canvas.clientHeight) {
                    canvas.width = canvas.clientWidth;
                    canvas.height = canvas.clientHeight;
                }

                ctx.clearRect(0, 0, canvas.width, canvas.height);
                const text = watermarkText || 'Loading secure player...';
                ctx.font = '600 15px "Inter", sans-serif';
                ctx.fillStyle = 'rgba(255, 255, 255, 0.45)';
                ctx.shadowColor = 'rgba(0, 0, 0, 0.4)';
                ctx.shadowBlur = 3;

                x += dx;
                y += dy;

                const textWidth = ctx.measureText(text).width;
                if (x < 10 || x + textWidth > canvas.width - 10) dx = -dx;
                if (y < 30 || y > canvas.height - 20) dy = -dy;

                x = Math.max(10, Math.min(x, canvas.width - textWidth - 10));
                y = Math.max(30, Math.min(y, canvas.height - 20));

                ctx.fillText(text, x, y);

                requestAnimationFrame(renderWatermark);
            }
            requestAnimationFrame(renderWatermark);

            const blockPlaybackWithViolation = (reason) => {
                video.pause();
                
                fetch('/api/student/security-violation', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        reason: reason,
                        otp: "${otp}",
                        playbackInfo: "${playbackInfo}",
                        videoId: "${videoId}"
                    })
                }).catch(() => {});

                if (player) {
                    player.destroy().catch(() => {});
                }

                wrapper.innerHTML = \`
                    <div class="tamper-overlay">
                        <div class="tamper-content">
                            <div class="tamper-title">Security Violation Detected</div>
                            <div class="tamper-desc">
                                Player component integrity breach detected (\${reason}). 
                                All streaming channels have been suspended for your protection.
                            </div>
                        </div>
                    </div>
                \`;
                observer.disconnect();
            };

            const observer = new MutationObserver((mutations) => {
                for (const mutation of mutations) {
                    if (mutation.type === 'childList') {
                        const hasCanvas = wrapper.contains(canvas);
                        const hasVideo = wrapper.contains(video);
                        if (!hasCanvas || !hasVideo) {
                            blockPlaybackWithViolation("element_removal");
                            return;
                        }
                    }
                    if (mutation.type === 'attributes') {
                        const opacityVal = canvas.style.opacity;
                        const displayVal = canvas.style.display;
                        const visibilityVal = canvas.style.visibility;
                        const transformVal = canvas.style.transform || '';
                        const filterVal = canvas.style.filter || '';
                        
                        if (displayVal === 'none' || 
                            visibilityVal === 'hidden' || 
                            opacityVal === '0' || 
                            (opacityVal !== '' && parseFloat(opacityVal) < 0.1) ||
                            canvas.style.width === '0px' ||
                            canvas.style.height === '0px' ||
                            transformVal.includes('scale(0)') ||
                            transformVal.includes('scale3d(0,') ||
                            filterVal.includes('opacity(0)') ||
                            canvas.getAttribute('width') === '0' ||
                            canvas.getAttribute('height') === '0'
                        ) {
                            blockPlaybackWithViolation("opacity_or_visibility_override");
                            return;
                        }
                    }
                }
            });

            observer.observe(wrapper, { attributes: true, childList: true, subtree: true });
            observer.observe(shadowRoot, { childList: true, subtree: true });
        });
    </script>
</body>
</html>
`;
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
