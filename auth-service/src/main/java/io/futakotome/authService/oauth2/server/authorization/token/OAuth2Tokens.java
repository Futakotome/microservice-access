package io.futakotome.authService.oauth2.server.authorization.token;

import io.futakotome.authService.oauth2.server.authorization.OAuth2Authorization;
import io.futakotome.authService.oauth2.server.authorization.Version;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * oauth2 token 集合
 *
 * @author futakotome
 * @see OAuth2Authorization
 * @see OAuth2TokenMetadata
 * @see AbstractOAuth2Token
 * @see OAuth2AccessToken
 * @see OAuth2RefreshToken
 * @see OidcIdToken
 */
public class OAuth2Tokens implements Serializable {
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
    private final Map<Class<? extends AbstractOAuth2Token>, OAuth2TokenHolder> tokens;


    protected OAuth2Tokens(Map<Class<? extends AbstractOAuth2Token>, OAuth2TokenHolder> tokens) {
        this.tokens = new HashMap<>(tokens);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder from(OAuth2Tokens tokens) {
        Assert.notNull(tokens, "tokens cannot be null");
        return new Builder(tokens.tokens);
    }

    @Nullable
    public OAuth2AccessToken getAccessToken() {
        return getToken(OAuth2AccessToken.class);
    }

    @Nullable
    public OAuth2RefreshToken getRefreshToken() {
        return getToken(OAuth2RefreshToken.class);
    }

    @Nullable
    @SuppressWarnings("unchecked")
    public <T extends AbstractOAuth2Token> T getToken(Class<T> tokenType) {
        Assert.notNull(tokenType, "tokenType cannot be null");
        OAuth2TokenHolder tokenHolder = this.tokens.get(tokenType);
        return tokenHolder != null ? (T) tokenHolder.getAbstractOAuth2Token() : null;
    }

    @Nullable
    @SuppressWarnings("unchecked")
    public <T extends AbstractOAuth2Token> T getToken(String token) {
        Assert.hasText(token, "token cannot be empty");
        OAuth2TokenHolder tokenHolder = this.tokens.values().stream()
                .filter(holder -> holder.getAbstractOAuth2Token().getTokenValue().equals(token))
                .findFirst()
                .orElse(null);
        return tokenHolder != null ? (T) tokenHolder.getAbstractOAuth2Token() : null;
    }

    @Nullable
    public <T extends AbstractOAuth2Token> OAuth2TokenMetadata getTokenMetadata(T token) {
        Assert.notNull(token, "token cannot be null");
        OAuth2TokenHolder tokenHolder = this.tokens.get(token.getClass());
        return (tokenHolder != null && tokenHolder.getAbstractOAuth2Token().equals(token)) ?
                tokenHolder.getoAuth2TokenMetadata() : null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OAuth2Tokens that = (OAuth2Tokens) o;
        return Objects.equals(tokens, that.tokens);
    }

    @Override
    public int hashCode() {

        return Objects.hash(tokens);
    }

    public static class Builder implements Serializable {
        private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
        private final Map<Class<? extends AbstractOAuth2Token>, OAuth2TokenHolder> tokens;

        protected Builder() {
            this.tokens = new HashMap<>();
        }

        protected Builder(Map<Class<? extends AbstractOAuth2Token>, OAuth2TokenHolder> tokens) {
            this.tokens = new HashMap<>(tokens);
        }

        public Builder idToken(OidcIdToken idToken) {
            return addToken(idToken, null);
        }

        public Builder idToken(OidcIdToken idToken, OAuth2TokenMetadata tokenMetadata) {
            return addToken(idToken, tokenMetadata);
        }

        public Builder accessToken(OAuth2AccessToken accessToken) {
            return addToken(accessToken, null);
        }

        public Builder accessToken(OAuth2AccessToken accessToken, OAuth2TokenMetadata tokenMetadata) {
            return addToken(accessToken, tokenMetadata);
        }

        public Builder refreshToken(OAuth2RefreshToken refreshToken) {
            return addToken(refreshToken, null);
        }

        public Builder refreshToken(OAuth2RefreshToken refreshToken, OAuth2TokenMetadata tokenMetadata) {
            return addToken(refreshToken, tokenMetadata);
        }

        public <T extends AbstractOAuth2Token> Builder token(T token) {
            return addToken(token, null);
        }

        public <T extends AbstractOAuth2Token> Builder token(T token, OAuth2TokenMetadata tokenMetadata) {
            return addToken(token, tokenMetadata);
        }

        protected Builder addToken(AbstractOAuth2Token token, OAuth2TokenMetadata tokenMetadata) {
            Assert.notNull(token, "token cannot be null");
            if (tokenMetadata == null) {
                tokenMetadata = OAuth2TokenMetadata.builder().build();
            }
            this.tokens.put(token.getClass(), new OAuth2TokenHolder(token, tokenMetadata));
            return this;
        }

        public OAuth2Tokens build() {
            return new OAuth2Tokens(this.tokens);
        }
    }

    protected static class OAuth2TokenHolder implements Serializable {
        private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
        private final AbstractOAuth2Token abstractOAuth2Token;
        private final OAuth2TokenMetadata oAuth2TokenMetadata;

        protected OAuth2TokenHolder(AbstractOAuth2Token abstractOAuth2Token, OAuth2TokenMetadata oAuth2TokenMetadata) {
            this.abstractOAuth2Token = abstractOAuth2Token;
            this.oAuth2TokenMetadata = oAuth2TokenMetadata;
        }

        protected AbstractOAuth2Token getAbstractOAuth2Token() {
            return abstractOAuth2Token;
        }

        protected OAuth2TokenMetadata getoAuth2TokenMetadata() {
            return oAuth2TokenMetadata;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            OAuth2TokenHolder that = (OAuth2TokenHolder) o;
            return Objects.equals(abstractOAuth2Token, that.abstractOAuth2Token) &&
                    Objects.equals(oAuth2TokenMetadata, that.oAuth2TokenMetadata);
        }

        @Override
        public int hashCode() {

            return Objects.hash(abstractOAuth2Token, oAuth2TokenMetadata);
        }
    }
}
