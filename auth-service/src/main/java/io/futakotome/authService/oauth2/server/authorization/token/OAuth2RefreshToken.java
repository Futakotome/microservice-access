package io.futakotome.authService.oauth2.server.authorization.token;

import org.springframework.security.oauth2.core.AbstractOAuth2Token;

import java.time.Instant;

/**
 * 框架里的refresh token 过期时间默认为null且不能设置，所以单独抽出来
 */
public class OAuth2RefreshToken extends AbstractOAuth2Token {
    public OAuth2RefreshToken(String tokenValue, Instant issuedAt, Instant expiresAt) {
        super(tokenValue, issuedAt, expiresAt);
    }
}
