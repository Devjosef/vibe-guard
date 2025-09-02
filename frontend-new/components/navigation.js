export function renderNavigation() {
    return `
        <nav class="fixed top-0 left-0 right-0 z-50 bg-background/95 backdrop-blur-sm border-b border-border">
            <div class="max-w-7xl mx-auto px-6 py-4">
                <div class="flex items-center justify-between">
                    <div class="flex items-center gap-2">
                        <div class="w-8 h-8 bg-black"></div>
                        <span class="text-xl font-black tracking-tight text-black">VIBE-GUARD</span>
                    </div>
                    <div class="hidden md:flex items-center gap-8">
                        <a href="features.html" class="text-black hover:text-primary transition-colors font-medium">
                            FEATURES
                        </a>
                        <a href="docs.html" class="text-black hover:text-primary transition-colors font-medium">
                            DOCS
                        </a>
                        <a href="https://github.com/Devjosef/vibe-guard" target="_blank" rel="noopener noreferrer" class="text-black hover:text-primary transition-colors font-medium">
                            GITHUB
                        </a>
                                            <a href="getting-started.html" class="bg-black text-white px-6 py-2 font-medium hover:bg-gray-800 transition-colors">
                        GET STARTED
                    </a>
                    </div>
                    <button class="md:hidden" id="mobile-menu-btn">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path>
                        </svg>
                    </button>
                </div>
                <div class="md:hidden hidden" id="mobile-menu">
                    <div class="py-4 space-y-4">
                        <a href="features.html" class="block text-black hover:text-primary transition-colors font-medium">
                            FEATURES
                        </a>
                        <a href="docs.html" class="block text-black hover:text-primary transition-colors font-medium">
                            DOCS
                        </a>
                        <a href="https://github.com/Devjosef/vibe-guard" target="_blank" rel="noopener noreferrer" class="block text-black hover:text-primary transition-colors font-medium">
                            GITHUB
                        </a>
                        <a href="getting-started.html" class="bg-black text-white px-6 py-2 font-medium hover:bg-gray-800 transition-colors w-full block text-center">
                            GET STARTED
                        </a>
                    </div>
                </div>
            </div>
        </nav>
    `;
}

export function initNavigation() {
    const mobileMenuBtn = document.getElementById('mobile-menu-btn');
    const mobileMenu = document.getElementById('mobile-menu');
    
    if (mobileMenuBtn && mobileMenu) {
        mobileMenuBtn.addEventListener('click', () => {
            mobileMenu.classList.toggle('hidden');
        });
    }
}
