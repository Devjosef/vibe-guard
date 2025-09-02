export function renderFooter() {
    return `
        <footer class="bg-white !bg-white border-t border-gray-200 py-12 px-6" style="background-color: #ffffff !important;">
            <div class="max-w-7xl mx-auto">
                <div class="grid grid-cols-1 md:grid-cols-4 gap-8">
                    <div class="space-y-4">
                        <div class="flex items-center gap-2">
                            <div class="w-6 h-6 bg-black"></div>
                            <span class="text-lg font-black tracking-tight text-black">VIBE-GUARD</span>
                        </div>
                        <p class="text-gray-600 text-sm">
                            Open-source security scanning for modern applications.
                        </p>
                    </div>
                    <div>
                        <h4 class="font-bold mb-4 text-black">PRODUCT</h4>
                        <div class="space-y-2 text-sm">
                            <a href="features.html" class="block text-gray-600 hover:text-black transition-colors">Features</a>
                            <a href="#" class="block text-gray-600 hover:text-black transition-colors">Changelog</a>
                        </div>
                    </div>
                    <div>
                        <h4 class="font-bold mb-4 text-black">RESOURCES</h4>
                        <div class="space-y-2 text-sm">
                            <a href="docs.html" class="block text-gray-600 hover:text-black transition-colors">Documentation</a>
                            <a href="performance.html" class="block text-gray-600 hover:text-black transition-colors">Metrics</a>
                        </div>
                    </div>
                    <div>
                        <div class="flex items-center gap-4 mb-4">
                            <a href="https://github.com/Devjosef/vibe-guard" target="_blank" rel="noopener noreferrer" class="text-gray-600 hover:text-black transition-colors">
                                <img src="assets/github-142-svgrepo-com.svg" alt="GitHub" class="w-8 h-8">
                            </a>
                            <a href="https://www.npmjs.com/package/vibe-guard" target="_blank" rel="noopener noreferrer" class="text-gray-600 hover:text-black transition-colors">
                                <img src="assets/npm-svgrepo-com.svg" alt="NPM" class="w-8 h-8">
                            </a>
                            <a href="#" class="text-gray-600 hover:text-black transition-colors">
                                <svg class="w-8 h-8" fill="currentColor" viewBox="0 0 24 24">
                                    <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515a.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0a12.64 12.64 0 0 0-.617-1.25a.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057a19.9 19.9 0 0 0 5.993 3.03a.078.078 0 0 0 .084-.028a14.09 14.09 0 0 0 1.226-1.994a.076.076 0 0 0-.041-.106a13.107 13.107 0 0 1-1.872-.892a.077.077 0 0 1-.008-.128a10.2 10.2 0 0 0 .372-.292a.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127a12.299 12.299 0 0 1-1.873.892a.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028a19.839 19.839 0 0 0 6.002-3.03a.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419c0-1.333.956-2.419 2.157-2.419c1.21 0 2.176 1.096 2.157 2.42c0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419c0-1.333.955-2.419 2.157-2.419c1.21 0 2.176 1.096 2.157 2.42c0 1.333-.946 2.418-2.157 2.418z"/>
                                </svg>
                            </a>
                        </div>
                    </div>
                </div>
                <div class="mt-12 pt-8 border-t border-gray-200 text-center">
                    <p class="text-gray-600 text-sm">
                        Copyright © 2025-present Josef Royem & Vibe-Guard contributors.
                    </p>
                </div>
            </div>
        </footer>
    `;
}

export function initFooter() {
    // Footer link handlers can go here
}
