package io.futakotome.authService.oauth2.server.authorization;

import io.futakotome.authService.oauth2.server.authorization.token.OAuth2AuthorizationCode;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final Map<OAuth2AuthorizationId, OAuth2Authorization> authorizations = new ConcurrentHashMap<>();

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        OAuth2AuthorizationId authorizationId = new OAuth2AuthorizationId(
                authorization.getRegisteredClientId(), authorization.getPrincipalName());
        this.authorizations.put(authorizationId, authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        OAuth2AuthorizationId authorizationId = new OAuth2AuthorizationId(
                authorization.getRegisteredClientId(), authorization.getPrincipalName());
        this.authorizations.remove(authorizationId, authorization);
    }

    @Override
    public OAuth2Authorization findByToken(String token, TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        return this.authorizations.values().stream()
                .filter(authorization -> hasToken(authorization, token, tokenType))
                .findFirst()
                .orElse(null);
    }

    private boolean hasToken(OAuth2Authorization authorization, String token, TokenType tokenType) {
        if (OAuth2AuthorizationAttributeNames.STATE.equals(tokenType.getValue())) {
            return token.equals(authorization.getAttribute(OAuth2AuthorizationAttributeNames.STATE));
        } else if (TokenType.AUTHORIZATION_CODE.equals(tokenType)) {
            OAuth2AuthorizationCode authorizationCode = authorization.getTokens().getToken(OAuth2AuthorizationCode.class);
            return authorizationCode != null && authorizationCode.getTokenValue().equals(token);
        } else if (TokenType.ACCESS_TOKEN.equals(tokenType)) {
            return authorization.getTokens().getAccessToken() != null &&
                    authorization.getTokens().getAccessToken().getTokenValue().equals(token);
        } else if (TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return authorization.getTokens().getRefreshToken() != null &&
                    authorization.getTokens().getRefreshToken().getTokenValue().equals(token);
        }

        return false;
    }

    private static class OAuth2AuthorizationId implements Serializable {
        private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
        private final String registeredClientId;
        private final String principalName;

        private OAuth2AuthorizationId(String registeredClientId, String principalName) {
            this.registeredClientId = registeredClientId;
            this.principalName = principalName;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            OAuth2AuthorizationId that = (OAuth2AuthorizationId) o;
            return Objects.equals(registeredClientId, that.registeredClientId) &&
                    Objects.equals(principalName, that.principalName);
        }

        @Override
        public int hashCode() {

            return Objects.hash(registeredClientId, principalName);
        }
    }
}
