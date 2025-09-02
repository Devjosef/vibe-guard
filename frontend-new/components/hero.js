export function renderHero() {
    return `
        <section id="hero" class="pt-24 pb-16 px-6 bg-white">
            <div class="max-w-7xl mx-auto">
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
                    <!-- Left side - Content -->
                    <div class="space-y-6">
                        <div>
                            <h1 class="text-7xl md:text-8xl lg:text-9xl font-black tracking-tighter text-black mb-4">
                                VIBE<br>GUARD
                            </h1>
                            <div class="w-32 h-2 bg-black"></div>
                        </div>
                        <p class="text-xl font-mono text-gray-500 uppercase tracking-wide mb-2">
                            SECURITY SCANNER
                        </p>
                        <p class="text-xl text-black max-w-lg">
                            Zero dependencies, instant setup, works everywhere. Optimized performance for security scanning.
                        </p>
                        <div class="flex flex-col sm:flex-row gap-4 pt-4">
                            <a href="getting-started.html" class="bg-black text-white px-8 py-4 text-lg font-medium hover:bg-gray-800 transition-colors border-2 border-black">
                                GET STARTED
                            </a>
                            <a href="docs.html" class="bg-white border-2 border-black text-black px-8 py-4 text-lg font-medium hover:bg-black hover:text-white transition-colors">
                                VIEW DOCS
                            </a>
                        </div>
                    </div>
                    
                    <!-- Right side - Terminal demo -->
                    <div class="bg-black border border-gray-800 p-8 rounded-lg">
                        <div class="font-mono text-sm space-y-2" id="hero-terminal">
                            <div class="text-green-500">$ npm install -g vibe-guard</div>
                            <div class="text-blue-500">$ vibe-guard scan ./src</div>
                            <div class="text-gray-500">✓ Scanning complete</div>
                            <div class="text-green-500">✓ 0 vulnerabilities found</div>
                            <div class="text-green-500">✓ Security score: 100%</div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    `;
}

export function initHero() {
    // Terminal typing effect will be handled by utils/animations.js
}
