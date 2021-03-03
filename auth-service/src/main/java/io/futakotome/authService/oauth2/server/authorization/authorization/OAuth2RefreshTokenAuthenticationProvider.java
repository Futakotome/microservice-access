package io.futakotome.authService.oauth2.server.authorization.authorization;

import io.futakotome.authService.oauth2.jwt.JwtEncoder;
import io.futakotome.authService.oauth2.server.authorization.OAuth2Authorization;
import io.futakotome.authService.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import io.futakotome.authService.oauth2.server.authorization.OAuth2AuthorizationService;
import io.futakotome.authService.oauth2.server.authorization.TokenType;
import io.futakotome.authService.oauth2.server.authorization.client.RegisteredClient;
import io.futakotome.authService.oauth2.server.authorization.config.TokenSettings;
import io.futakotome.authService.oauth2.server.authorization.token.OAuth2RefreshToken;
import io.futakotome.authService.oauth2.server.authorization.token.OAuth2Tokens;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.Set;

public class OAuth2RefreshTokenAuthenticationProvider implements AuthenticationProvider {
    private final OAuth2AuthorizationService authorizationService;
    private final JwtEncoder jwtEncoder;

    public OAuth2RefreshTokenAuthenticationProvider(OAuth2AuthorizationService authorizationService, JwtEncoder jwtEncoder) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
        this.authorizationService = authorizationService;
        this.jwtEncoder = jwtEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2RefreshTokenAuthenticationToken refreshTokenAuthentication = (OAuth2RefreshTokenAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(refreshTokenAuthentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) refreshTokenAuthentication.getPrincipal();
        }
        if (clientPrincipal == null || !clientPrincipal.isAuthenticated()) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
        }
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        OAuth2Authorization authorization = this.authorizationService.findByToken(refreshTokenAuthentication.getRefreshToken(), TokenType.REFRESH_TOKEN);
        if (authorization == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
        }

        if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
        }

        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT));
        }

        Instant refreshTokenExpiresAt = authorization.getTokens().getRefreshToken().getExpiresAt();
        if (refreshTokenExpiresAt.isBefore(Instant.now())) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
        }

        Set<String> scopes = refreshTokenAuthentication.getScopes();
        Set<String> authorizedScopes = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZED_SCOPES);
        if (!authorizedScopes.containsAll(scopes)) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE));
        }
        if (scopes.isEmpty()) {
            scopes = authorizedScopes;
        }

        Jwt jwt = OAuth2TokenIssuerUtil.issueJwtAccessToken(this.jwtEncoder, authorization.getPrincipalName(), registeredClient.getClientId(), scopes);
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), scopes);
        jwt = OAuth2TokenIssuerUtil.issueIdToken(this.jwtEncoder, authorization.getPrincipalName());
        OidcIdToken idToken = new OidcIdToken(jwt.getTokenValue(),
                jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaims());

        TokenSettings tokenSettings = registeredClient.getTokenSettings();
        OAuth2RefreshToken refreshToken;
        if (tokenSettings.reuseRefreshTokens()) {
            refreshToken = authorization.getTokens().getRefreshToken();
        } else {
            refreshToken = OAuth2TokenIssuerUtil.issueRefreshToken(tokenSettings.refreshTokenTimeToLive());
        }

        authorization = OAuth2Authorization.from(authorization)
                .tokens(OAuth2Tokens.from(authorization.getTokens())
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .idToken(idToken).build())
                .attribute(OAuth2AuthorizationAttributeNames.ACCESS_TOKEN_ATTRIBUTES, jwt)
                .build();
        this.authorizationService.save(authorization);
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, idToken, refreshToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
