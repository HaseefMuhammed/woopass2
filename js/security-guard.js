/**
 * ============================================================================
 * WOO PASS — Platform Security Guard (js/security-guard.js)
 * Anti-Inspection, DevTools Blocking, and Screen Capture Deterrent
 * ============================================================================
 */

/* ============================================
   Detect Touch Devices (Mobile / Tablet)
============================================ */
const isTouchDevice =
    'ontouchstart' in window ||
    navigator.maxTouchPoints > 0;

/* ============================================
   🔁 Redirect Function
============================================ */
function redirect() {
    window.location.href =
        "https://theajack.github.io/disable-devtool/404.html?h=WooPass";
}

/* ============================================
   🚫 Disable Right Click (Desktop Only)
============================================ */
if (!isTouchDevice) {
    document.addEventListener("contextmenu", function (e) {
        e.preventDefault();
    });
}

/* ============================================
   🚫 Disable DevTools Shortcuts & Screen Capture Keys
============================================ */
if (!isTouchDevice) {

    document.addEventListener("keydown", function (e) {

        // F12
        if (e.key === "F12" || e.keyCode === 123) {
            e.preventDefault();
            redirect();
        }

        // Ctrl + U (View Source)
        if (e.ctrlKey && e.key.toLowerCase() === "u") {
            e.preventDefault();
            redirect();
        }

        // Ctrl + Shift + I (Inspect)
        if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "i") {
            e.preventDefault();
            redirect();
        }

        // Ctrl + Shift + J (Console)
        if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "j") {
            e.preventDefault();
            redirect();
        }

        // Ctrl + Shift + C (Element Inspector)
        if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "c") {
            e.preventDefault();
            redirect();
        }

        // Ctrl + S (Save Page)
        if (e.ctrlKey && e.key.toLowerCase() === "s") {
            e.preventDefault();
        }

        // Ctrl + P (Print)
        if (e.ctrlKey && e.key.toLowerCase() === "p") {
            e.preventDefault();
        }

        // PrintScreen Key
        if (e.key === "PrintScreen") {
            e.preventDefault();
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText('');
            }
        }

    });

}

/* ============================================
   🚫 Detect DevTools Window Resize (Desktop Only)
============================================ */
if (!isTouchDevice) {

    setInterval(function () {

        if (
            window.outerWidth - window.innerWidth > 160 ||
            window.outerHeight - window.innerHeight > 160
        ) {
            redirect();
        }

    }, 1000);

}
