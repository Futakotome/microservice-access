package io.futakotome.authService.oauth2.server.authorization.token;

import org.springframework.security.oauth2.core.AbstractOAuth2Token;

import java.time.Instant;

/**
 * {@link AbstractOAuth2Token}的一种实现,目前只有Authorization code 授权方式一种
 *
 * @author futakotome
 * @see AbstractOAuth2Token
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 */
public class OAuth2AuthorizationCode extends AbstractOAuth2Token {
    public OAuth2AuthorizationCode(String tokenValue, Instant issuedAt, Instant expiresAt) {
        super(tokenValue, issuedAt, expiresAt);
    }
}
