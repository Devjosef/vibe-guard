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
