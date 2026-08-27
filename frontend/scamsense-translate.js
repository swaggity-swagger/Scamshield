(function () {
    const LANGUAGE_KEY = "scamsense-language";
    const USER_KEY = "scamsense-user";
    const SUPPORTED_LANGUAGES = ["en", "hi", "mr"];

    function safeJsonParse(value) {
        try {
            return JSON.parse(value);
        } catch {
            return null;
        }
    }

    function getStoredUser() {
        return (
            safeJsonParse(localStorage.getItem(USER_KEY)) ||
            safeJsonParse(sessionStorage.getItem(USER_KEY))
        );
    }

    function updateLoginLinks() {
        const user = getStoredUser();
        const name = (user && String(user.name || user.email || "").trim()) || "";

        if (!name) {
            return;
        }

        const initial = name.charAt(0).toUpperCase();

        document.querySelectorAll('a[href$="login.html"]').forEach((link) => {
            link.textContent = initial;
            link.setAttribute("aria-label", `Signed in as ${name}`);
            link.setAttribute("title", name);
            link.setAttribute("translate", "no");
            link.classList.add("notranslate");
            link.href = "history.html";
        });
    }

    function protectFunctionalText() {
        document.querySelectorAll(".material-symbols-outlined").forEach((icon) => {
            icon.setAttribute("translate", "no");
            icon.classList.add("notranslate");
        });

        document
            .querySelectorAll(
                [
                    "#results-section",
                    "#results-card",
                    "#risk-card",
                    "#error-box",
                    "#error-message",
                    "#status-message",
                    "#loading-state",
                    "#success-panel",
                ].join(",")
            )
            .forEach((element) => {
                element.setAttribute("translate", "no");
                element.classList.add("notranslate");
            });
    }

    function getLanguageSelector() {
        return (
            document.getElementById("language-selector") ||
            document.getElementById("languageSelector")
        );
    }

    function ensureGoogleTranslateContainer() {
        if (document.getElementById("google_translate_element")) {
            return;
        }

        const container = document.createElement("div");
        container.id = "google_translate_element";
        container.setAttribute("aria-hidden", "true");
        container.style.position = "fixed";
        container.style.left = "-9999px";
        container.style.top = "0";
        container.style.width = "1px";
        container.style.height = "1px";
        container.style.overflow = "hidden";
        document.body.appendChild(container);
    }

    function hideGoogleTranslateChrome() {
        if (document.getElementById("scamsense-translate-style")) {
            return;
        }

        const style = document.createElement("style");
        style.id = "scamsense-translate-style";
        style.textContent = `
            .goog-te-banner-frame,
            .goog-te-gadget,
            .goog-logo-link,
            iframe.skiptranslate {
                display: none !important;
            }

            body {
                top: 0 !important;
            }
        `;
        document.head.appendChild(style);
    }

    function setGoogleLanguage(language) {
        const combo = document.querySelector(".goog-te-combo");

        if (!combo) {
            return false;
        }

        if (combo.value !== language) {
            combo.value = language;
            combo.dispatchEvent(new Event("change", { bubbles: true }));
        }

        document.documentElement.lang = language;
        return true;
    }

    function setTranslateCookie(language) {
        const value = language === "en" ? "/en/en" : `/en/${language}`;
        document.cookie = `googtrans=${value}; path=/`;
    }

    function pageHasTranslatedText() {
        return /[\u0900-\u097F]/.test(document.body.innerText);
    }

    function reloadIfTranslationDidNotApply(language) {
        if (language === "en" || pageHasTranslatedText()) {
            return;
        }

        const reloadKey = `scamsense-translate-reloaded-${language}`;

        if (sessionStorage.getItem(reloadKey) === location.pathname) {
            return;
        }

        sessionStorage.setItem(reloadKey, location.pathname);
        location.reload();
    }

    function syncLanguage(language) {
        const normalized = SUPPORTED_LANGUAGES.includes(language) ? language : "en";
        const selector = getLanguageSelector();

        if (selector && selector.value !== normalized) {
            selector.value = normalized;
        }

        setTranslateCookie(normalized);
        document.documentElement.lang = normalized;

        if (!setGoogleLanguage(normalized)) {
            setTimeout(() => setGoogleLanguage(normalized), 400);
            setTimeout(() => setGoogleLanguage(normalized), 1200);
        }

        setTimeout(() => reloadIfTranslationDidNotApply(normalized), 3000);
    }

    function loadGoogleTranslate() {
        if (document.getElementById("scamsense-google-translate-script")) {
            return;
        }

        window.googleTranslateElementInit = function () {
            new window.google.translate.TranslateElement(
                {
                    pageLanguage: "en",
                    includedLanguages: "en,hi,mr",
                    autoDisplay: false,
                },
                "google_translate_element"
            );

            syncLanguage(localStorage.getItem(LANGUAGE_KEY) || "en");
        };

        const script = document.createElement("script");
        script.id = "scamsense-google-translate-script";
        script.src =
            "https://translate.google.com/translate_a/element.js?cb=googleTranslateElementInit";
        script.async = true;
        document.head.appendChild(script);
    }

    function initLanguageSelector() {
        const selector = getLanguageSelector();
        const savedLanguage = localStorage.getItem(LANGUAGE_KEY);

        if (selector && savedLanguage && SUPPORTED_LANGUAGES.includes(savedLanguage)) {
            selector.value = savedLanguage;
        }

        if (selector) {
            selector.addEventListener("change", () => {
                const language = SUPPORTED_LANGUAGES.includes(selector.value)
                    ? selector.value
                    : "en";

                localStorage.setItem(LANGUAGE_KEY, language);
                syncLanguage(language);
            });
        }

        syncLanguage((selector && selector.value) || savedLanguage || "en");
    }

    document.addEventListener("DOMContentLoaded", () => {
        protectFunctionalText();
        updateLoginLinks();
        hideGoogleTranslateChrome();
        ensureGoogleTranslateContainer();
        initLanguageSelector();
        loadGoogleTranslate();
    });
})();
