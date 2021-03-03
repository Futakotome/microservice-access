package io.futakotome.authService.oauth2.server.authorization.authorization;

import io.futakotome.authService.oauth2.server.authorization.OAuth2Authorization;
import io.futakotome.authService.oauth2.server.authorization.token.OAuth2AuthorizationCode;
import io.futakotome.authService.oauth2.server.authorization.token.OAuth2TokenMetadata;
import io.futakotome.authService.oauth2.server.authorization.token.OAuth2Tokens;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

final class OAuth2AuthenticationProviderUtils {
    private OAuth2AuthenticationProviderUtils() {
    }

    static <T extends AbstractOAuth2Token> OAuth2Authorization invalidate(OAuth2Authorization authorization, T token) {
        OAuth2Tokens.Builder builder = OAuth2Tokens.from(authorization.getTokens()).token(token, OAuth2TokenMetadata.builder().invalidated().build());

        if (OAuth2RefreshToken.class.isAssignableFrom(token.getClass())) {
            builder.token(authorization.getTokens().getAccessToken(), OAuth2TokenMetadata.builder().invalidated().build());
            OAuth2AuthorizationCode authorizationCode = authorization.getTokens().getToken(OAuth2AuthorizationCode.class);
            if (authorizationCode != null && !authorization.getTokens().getTokenMetadata(authorizationCode).isInvalidated()) {
                builder.token(authorizationCode, OAuth2TokenMetadata.builder().invalidated().build());
            }
        }
        return OAuth2Authorization.from(authorization).tokens(builder.build()).build();
    }
}
