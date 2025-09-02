// Import all components
import { renderNavigation, initNavigation } from './components/navigation.js';
import { renderHero, initHero } from './components/hero.js';
import { renderThreatDetection, initThreatDetection } from './components/threat-detection.js';
import { renderPerformance, initPerformance } from './components/performance.js';
import { renderCTA, initCTA } from './components/cta.js';
import { renderFooter, initFooter } from './components/footer.js';

// Import utilities
import { initTerminalEffect, initScrollAnimations } from './utils/animations.js';
import { initSmoothScrolling, initScrollToTop } from './utils/scroll.js';

// Main app initialization
function initApp() {
    // Hide loading, show app
    const loading = document.getElementById('loading');
    const app = document.getElementById('app');
    
    if (loading) loading.classList.add('hidden');
    if (app) app.classList.remove('hidden');
    
    // Render all components
    app.innerHTML = `
        ${renderNavigation()}
        <main>
            ${renderHero()}
            ${renderThreatDetection()}
            ${renderPerformance()}

            ${renderCTA()}
        </main>
        ${renderFooter()}
    `;

    // Initialize all components
    initNavigation();
    initHero();
    initThreatDetection();
    initPerformance();

    initCTA();
    initFooter();

    // Initialize utilities
    initTerminalEffect();
    initScrollAnimations();
    initSmoothScrolling();
    initScrollToTop();
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}
