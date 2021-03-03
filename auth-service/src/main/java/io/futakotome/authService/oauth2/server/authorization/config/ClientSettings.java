package io.futakotome.authService.oauth2.server.authorization.config;

import java.util.HashMap;
import java.util.Map;

public class ClientSettings extends Settings {
    private static final String CLIENT_SETTING_BASE = "spring.security.oauth2.authorization-server.client.";
    public static final String REQUIRE_PROOF_KEY = CLIENT_SETTING_BASE.concat("require-proof-key");
    public static final String REQUIRE_USER_CONSENT = CLIENT_SETTING_BASE.concat("require-user-consent");

    public ClientSettings() {
        this(defaultSettings());
    }

    public ClientSettings(Map<String, Object> settings) {
        super(settings);
    }

    public boolean requireProofKey() {
        return setting(REQUIRE_PROOF_KEY);
    }

    public ClientSettings requireProofKey(boolean requireProofKey) {
        setting(REQUIRE_PROOF_KEY, requireProofKey);
        return this;
    }

    public boolean requireUserConsent() {
        return setting(REQUIRE_USER_CONSENT);
    }

    public ClientSettings requireUserConsent(boolean requireUserConsent) {
        setting(REQUIRE_USER_CONSENT, requireUserConsent);
        return this;
    }

    protected static Map<String, Object> defaultSettings() {
        Map<String, Object> settings = new HashMap<>();
        settings.put(REQUIRE_PROOF_KEY, false);
        settings.put(REQUIRE_USER_CONSENT, false);
        return settings;
    }
}
