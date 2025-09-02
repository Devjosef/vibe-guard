export function renderCTA() {
    return `
        <section id="cta" class="py-16 px-6 bg-black !bg-black text-white cta-jet-black" style="background-color: #000000 !important; background: #000000 !important;">
            <div class="max-w-4xl mx-auto text-center">
                <h2 class="text-4xl md:text-5xl font-black tracking-tight mb-6 text-white">
                    SECURE YOUR CODE
                </h2>
                <div class="w-24 h-2 bg-white mx-auto mb-6"></div>
                <p class="text-xl mb-8 opacity-90 text-white">
                    Join hundreds of developers who use Vibe-Guard to protect their applications from security vulnerabilities.
                </p>
                
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                    <div class="bg-white/10 border border-white/20 p-4 rounded-lg">
                        <div class="text-sm font-mono text-white mb-2">NPM</div>
                        <div class="text-xs font-mono text-white/80">npm install -g vibe-guard</div>
                    </div>
                    
                    <div class="bg-white/10 border border-white/20 p-4 rounded-lg">
                        <div class="text-sm font-mono text-white mb-2">YARN</div>
                        <div class="text-xs font-mono text-white/80">yarn global add vibe-guard</div>
                    </div>
                    
                    <div class="bg-white/10 border border-white/20 p-4 rounded-lg">
                        <div class="text-sm font-mono text-white mb-2">PNPM</div>
                        <div class="text-xs font-mono text-white/80">pnpm add -g vibe-guard</div>
                    </div>
                </div>
                
                <div class="flex flex-col sm:flex-row gap-4 justify-center mb-8">
                    <button class="bg-white text-black px-8 py-4 text-lg font-bold hover:bg-gray-200 transition-colors">
                        START SCANNING NOW
                    </button>
                    <a href="docs.html" class="border border-white text-white px-8 py-4 text-lg font-bold hover:bg-white hover:text-black transition-colors">
                        VIEW DOCUMENTATION
                    </a>
                </div>
                
                <div class="bg-black border border-black p-6 mt-8 max-w-4xl mx-auto">
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-8 text-center">
                        <div>
                            <div class="text-2xl font-bold text-white mb-1">500+</div>
                            <div class="text-sm text-white">Downloads</div>
                        </div>
                        <div>
                            <div class="text-2xl font-bold text-white mb-1">1K+</div>
                            <div class="text-sm text-white">Files Scanned</div>
                        </div>
                        <div>
                            <div class="text-2xl font-bold text-white mb-1">100%</div>
                            <div class="text-sm text-white">Open Source</div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        
        <!-- Line break between CTA and footer -->
        <div class="py-16 bg-white"></div>
    `;
}

export function initCTA() {
    // CTA button handlers can go here
    const startScanningBtn = document.querySelector('#cta button');
    
    if (startScanningBtn) {
        startScanningBtn.addEventListener('click', () => {
            // Handle start scanning action
            console.log('Start scanning clicked');
        });
    }
}
