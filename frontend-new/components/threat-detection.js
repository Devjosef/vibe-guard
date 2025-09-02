export function renderThreatDetection() {
    return `
        <section id="features" class="py-16 px-6 bg-gray-200">
            <div class="max-w-7xl mx-auto">
                <div class="text-center mb-16">
                    <h2 class="text-4xl md:text-5xl font-black tracking-tight text-black mb-4">
                        THREAT DETECTION
                    </h2>
                    <div class="w-24 h-2 bg-black mx-auto mb-6"></div>
                    <p class="text-xl text-gray-500 max-w-2xl mx-auto">
                        Comprehensive security scanning across multiple vulnerability categories
                    </p>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                    <!-- Feature Cards -->
                    <div class="bg-white border border-gray-200 p-6 hover:border-2 hover:border-black transition-colors relative">
                        <div class="flex justify-between items-center mb-4">
                            <div class="text-xs font-mono text-black">PROMPT_INJECTION</div>
                            <div class="w-3 h-3 bg-green-500 rounded-full"></div>
                        </div>
                        <h3 class="text-xl font-bold text-black mb-3">Prompt Injection</h3>
                        <p class="text-black">Detect AI/ML prompt injection attacks and malicious input manipulation.</p>
                    </div>
                    
                    <div class="bg-white border border-gray-200 p-6 hover:border-2 hover:border-black transition-colors relative">
                        <div class="flex justify-between items-center mb-4">
                            <div class="text-xs font-mono text-black">DIRECTORY_TRAVERSAL</div>
                            <div class="w-3 h-3 bg-green-500 rounded-full"></div>
                        </div>
                        <h3 class="text-xl font-bold text-black mb-3">Directory Traversal</h3>
                        <p class="text-black">Find path traversal vulnerabilities that expose sensitive files.</p>
                    </div>
                    
                    <div class="bg-white border border-gray-200 p-6 hover:border-2 hover:border-black transition-colors relative">
                        <div class="flex justify-between items-center mb-4">
                            <div class="text-xs font-mono text-black">INSECURE_FILE_UPLOAD</div>
                            <div class="w-3 h-3 bg-green-500 rounded-full"></div>
                        </div>
                        <h3 class="text-xl font-bold text-black mb-3">Insecure File Upload</h3>
                        <p class="text-black">Detect dangerous file upload vulnerabilities and malicious files.</p>
                    </div>
                    
                    <div class="bg-white border border-gray-200 p-6 hover:border-2 hover:border-black transition-colors relative">
                        <div class="flex justify-between items-center mb-4">
                            <div class="text-xs font-mono text-black">MCP_SERVER_SECURITY</div>
                            <div class="w-3 h-3 bg-green-500 rounded-full"></div>
                        </div>
                        <h3 class="text-xl font-bold text-black mb-3">MCP Server Security</h3>
                        <p class="text-black">Validate Model Context Protocol server configurations and security.</p>
                    </div>
                    
                    <div class="bg-white border border-gray-200 p-6 hover:border-2 hover:border-black transition-colors relative">
                        <div class="flex justify-between items-center mb-4">
                            <div class="text-xs font-mono text-black">AI_GENERATED_CODE_VALIDATION</div>
                            <div class="w-3 h-3 bg-green-500 rounded-full"></div>
                        </div>
                        <h3 class="text-xl font-bold text-black mb-3">AI Code Validation</h3>
                        <p class="text-black">Validate AI-generated code for security vulnerabilities and best practices.</p>
                    </div>
                    
                    <div class="bg-white border border-gray-200 p-6 hover:border-2 hover:border-black transition-colors relative">
                        <div class="flex justify-between items-center mb-4">
                            <div class="text-xs font-mono text-black">INSECURE_RANDOM_GENERATION</div>
                            <div class="w-3 h-3 bg-green-500 rounded-full"></div>
                        </div>
                        <h3 class="text-xl font-bold text-black mb-3">Insecure Random Generation</h3>
                        <p class="text-black">Detect weak random number generation and cryptographic vulnerabilities.</p>
                    </div>
                </div>
                
                <!-- Stats Box -->
                <div class="bg-black border border-black p-6 mt-8 max-w-4xl mx-auto">
                    <div class="grid grid-cols-1 md:grid-cols-4 gap-6 text-center">
                        <div>
                            <div class="text-2xl font-black text-white mb-1">15+</div>
                            <div class="text-sm text-white">Threat Types</div>
                        </div>
                        <div>
                            <div class="text-2xl font-black text-white mb-1">< 1s</div>
                            <div class="text-sm text-white">Scan Time</div>
                        </div>
                        <div>
                            <div class="text-2xl font-black text-white mb-1">0</div>
                            <div class="text-sm text-white">Dependencies</div>
                        </div>
                        <div>
                            <div class="text-2xl font-black text-white mb-1">100%</div>
                            <div class="text-sm text-white">Coverage</div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    `;
}

export function initThreatDetection() {
    // Any threat detection specific interactions can go here
}
