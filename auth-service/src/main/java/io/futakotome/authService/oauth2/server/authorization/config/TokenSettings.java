package io.futakotome.authService.oauth2.server.authorization.config;

import org.springframework.util.Assert;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * 令牌设置
 *
 * @author futakotome
 * @see Settings
 */
public class TokenSettings extends Settings {
    private static final String TOKEN_SETTING_BASE = "spring.security.oauth2.authorization-server.token.";
    public static final String ACCESS_TOKEN_TIME_TO_LIVE = TOKEN_SETTING_BASE.concat("access-token-time-to-live");
    public static final String ENABLE_REFRESH_TOKENS = TOKEN_SETTING_BASE.concat("enable-refresh-tokens");
    public static final String REUSE_REFRESH_TOKENS = TOKEN_SETTING_BASE.concat("reuse-refresh-tokens");
    public static final String REFRESH_TOKEN_TIME_TO_LIVE = TOKEN_SETTING_BASE.concat("refresh-token-time-to-live");

    public TokenSettings() {
        this(defaultSettings());
    }

    public TokenSettings(Map<String, Object> settings) {
        super(settings);
    }

    public Duration accessTokenTimeToLive() {
        return setting(ACCESS_TOKEN_TIME_TO_LIVE);
    }

    public TokenSettings accessTokenTimeToLive(Duration accessTokenTimeToLive) {
        Assert.notNull(accessTokenTimeToLive, "accessTokenTimeToLive cannot be null");
        Assert.isTrue(accessTokenTimeToLive.getSeconds() > 0, "accessTokenTimeToLive must be greater than Duration.ZERO");
        setting(ACCESS_TOKEN_TIME_TO_LIVE, accessTokenTimeToLive);
        return this;
    }

    public boolean enableRefreshTokens() {
        return setting(ENABLE_REFRESH_TOKENS);
    }

    public TokenSettings enableRefreshTokens(boolean enableRefreshTokens) {
        setting(ENABLE_REFRESH_TOKENS, enableRefreshTokens);
        return this;
    }

    public boolean reuseRefreshTokens() {
        return setting(REUSE_REFRESH_TOKENS);
    }

    public TokenSettings reuseRefreshTokens(boolean reuseRefreshTokens) {
        setting(REUSE_REFRESH_TOKENS, reuseRefreshTokens);
        return this;
    }

    public Duration refreshTokenTimeToLive() {
        return setting(REFRESH_TOKEN_TIME_TO_LIVE);
    }

    public TokenSettings refreshTokenTimeToLive(Duration refreshTokenTimeToLive) {
        Assert.notNull(refreshTokenTimeToLive, "refreshTokenTimeToLive cannot be null");
        Assert.isTrue(refreshTokenTimeToLive.getSeconds() > 0, "refreshTokenTimeToLive must be greater than Duration.ZERO");
        setting(REFRESH_TOKEN_TIME_TO_LIVE, refreshTokenTimeToLive);
        return this;
    }

    protected static Map<String, Object> defaultSettings() {
        Map<String, Object> settings = new HashMap<>();
        settings.put(ACCESS_TOKEN_TIME_TO_LIVE, Duration.ofMinutes(5));
        settings.put(ENABLE_REFRESH_TOKENS, true);
        settings.put(REUSE_REFRESH_TOKENS, true);
        settings.put(REFRESH_TOKEN_TIME_TO_LIVE, Duration.ofMinutes(60));
        return settings;
    }
}
