export function renderPerformance() {
    return `
        <section id="performance" class="py-20 px-6 bg-white">
            <div class="max-w-7xl mx-auto">
                <div class="text-center mb-16">
                    <h2 class="text-4xl font-black text-gray-900 mb-4">BUILT FOR SPEED</h2>
                    <div class="w-24 h-2 bg-gray-900 mx-auto mb-6"></div>
                    <p class="text-xl text-gray-600 max-w-3xl mx-auto">
                        Performance without the complexity
                    </p>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-8 mb-16">
                    <div class="bg-white border border-gray-200 p-8 hover:border-primary transition-colors">
                        <div class="flex justify-between items-start mb-2">
                            <div class="text-xl font-mono font-bold text-black">ZERO DEPENDENCIES</div>
                            <div class="text-right">
                                <div class="text-3xl font-black text-black">0 MB</div>
                                <div class="text-xs text-gray-500">ADDITIONAL PACKAGES</div>
                            </div>
                        </div>
                        <p class="text-black">No external libraries or frameworks required. Pure, optimized code.</p>
                    </div>
                    
                    <div class="bg-white border border-gray-200 p-8 hover:border-primary transition-colors">
                        <div class="flex justify-between items-start mb-2">
                            <div class="text-xl font-mono font-bold text-black">INSTANT SETUP</div>
                            <div class="text-right">
                                <div class="text-3xl font-black text-black">< 5s</div>
                                <div class="text-xs text-gray-500">SETUP TIME</div>
                            </div>
                        </div>
                        <p class="text-black">Single command installation. Ready to scan in seconds.</p>
                    </div>
                    
                    <div class="bg-white border border-gray-200 p-8 hover:border-primary transition-colors">
                        <div class="flex justify-between items-start mb-2">
                            <div class="text-xl font-mono font-bold text-black">WORKS EVERYWHERE</div>
                            <div class="text-right">
                                <div class="text-3xl font-black text-black">100%</div>
                                <div class="text-xs text-gray-500">PLATFORM COVERAGE</div>
                            </div>
                        </div>
                        <p class="text-black">Cross-platform compatibility. Linux, macOS, Windows support.</p>
                    </div>
                    
                    <div class="bg-white border border-gray-200 p-8 hover:border-primary transition-colors">
                        <div class="flex justify-between items-start mb-2">
                            <div class="text-xl font-mono font-bold text-black">OPTIMIZED PERFORMANCE</div>
                            <div class="text-right">
                                <div class="text-3xl font-black text-black">< 1s</div>
                                <div class="text-xs text-gray-500">AVERAGE SCAN TIME</div>
                            </div>
                        </div>
                        <p class="text-black">Blazing fast scans with minimal resource usage.</p>
                    </div>
                </div>

                <div class="bg-gray-200 p-8 lg:p-12">
                    <div class="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
                        <div>
                            <h3 class="text-3xl font-black tracking-tight text-black mb-4">
                                INSTALLATION
                            </h3>
                            <p class="text-gray-500 mb-6">
                                Get started with Vibe-Guard in under 30 seconds. No configuration files, 
                                no complex setup processes, no hidden dependencies.
                            </p>
                            <ul class="space-y-3 list-disc list-inside">
                                <li class="text-black text-sm">Install globally via npm</li>
                                <li class="text-black text-sm">Run scan command</li>
                                <li class="text-black text-sm">View security report</li>
                            </ul>
                        </div>
                        
                        <div class="bg-black text-white p-4 font-mono" id="installation-terminal">
                            <div class="space-y-2 text-xs">
                                <div class="text-green-400"># Step 1: Install Vibe-Guard</div>
                                <div class="text-white">$ npm install -g vibe-guard</div>
                                <div class="text-gray-400">✓ Installation complete (4.2s)</div>
                                <div class="mt-4 text-green-400"># Step 2: Run security scan</div>
                                <div class="text-white">$ vibe-guard scan --target ./project</div>
                                <div class="text-gray-400">✓ Scanning 47 files...</div>
                                <div class="text-gray-400">✓ Analysis complete (0.8s)</div>
                                <div class="mt-4 text-green-400"># Step 3: View results</div>
                                <div class="text-white">$ vibe-guard report</div>
                                <div class="text-gray-400">Security Score: 95/100</div>
                                <div class="text-gray-400">Issues found: 2 medium</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    `;
}

export function initPerformance() {
    // Any performance section specific interactions can go here
}
