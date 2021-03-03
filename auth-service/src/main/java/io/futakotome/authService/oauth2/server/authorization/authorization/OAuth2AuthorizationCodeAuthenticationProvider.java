package io.futakotome.authService.oauth2.server.authorization.authorization;

import io.futakotome.authService.oauth2.jwt.JwtEncoder;
import io.futakotome.authService.oauth2.server.authorization.OAuth2Authorization;
import io.futakotome.authService.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import io.futakotome.authService.oauth2.server.authorization.OAuth2AuthorizationService;
import io.futakotome.authService.oauth2.server.authorization.TokenType;
import io.futakotome.authService.oauth2.server.authorization.client.RegisteredClient;
import io.futakotome.authService.oauth2.server.authorization.client.RegisteredClientRepository;
import io.futakotome.authService.oauth2.server.authorization.token.OAuth2AuthorizationCode;
import io.futakotome.authService.oauth2.server.authorization.token.OAuth2RefreshToken;
import io.futakotome.authService.oauth2.server.authorization.token.OAuth2TokenMetadata;
import io.futakotome.authService.oauth2.server.authorization.token.OAuth2Tokens;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Set;

/**
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request</a>
 */
public class OAuth2AuthorizationCodeAuthenticationProvider implements AuthenticationProvider {
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final JwtEncoder jwtEncoder;

    public OAuth2AuthorizationCodeAuthenticationProvider(RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService authorizationService, JwtEncoder jwtEncoder) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.jwtEncoder = jwtEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = (OAuth2AuthorizationCodeAuthenticationToken) authentication;

        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authorizationCodeAuthentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authorizationCodeAuthentication.getPrincipal();
        }
        if (clientPrincipal == null || !clientPrincipal.isAuthenticated()) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
        }
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        OAuth2Authorization authorization = this.authorizationService.findByToken(authorizationCodeAuthentication.getCode(), TokenType.AUTHORIZATION_CODE);
        if (authorization == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
        }
        OAuth2AuthorizationCode authorizationCode = authorization.getTokens().getToken(OAuth2AuthorizationCode.class);
        OAuth2TokenMetadata authorizationCodeMetadata = authorization.getTokens().getTokenMetadata(authorizationCode);
        OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST);
        if (!registeredClient.getClientId().equals(authorizationRequest.getClientId())) {
            if (!authorizationCodeMetadata.isInvalidated()) {
                authorization = OAuth2AuthenticationProviderUtils.invalidate(authorization, authorizationCode);
                this.authorizationService.save(authorization);
            }
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
        }

        if (StringUtils.hasText(authorizationRequest.getRedirectUri()) &&
                !authorizationRequest.getRedirectUri().equals(authorizationCodeAuthentication.getRedirectUri())) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
        }

        if (authorizationCodeMetadata.isInvalidated()) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
        }
        Set<String> authorizedScopes = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZED_SCOPES);
        Jwt jwt = OAuth2TokenIssuerUtil
                .issueJwtAccessToken(this.jwtEncoder, authorization.getPrincipalName(), registeredClient.getClientId(), authorizedScopes);
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), authorizedScopes);
        OAuth2Tokens.Builder tokensBuilder = OAuth2Tokens.from(authorization.getTokens())
                .accessToken(accessToken);

        jwt = OAuth2TokenIssuerUtil.issueIdToken(this.jwtEncoder, authorization.getPrincipalName());
        OidcIdToken idToken = new OidcIdToken(jwt.getTokenValue(),
                jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaims());
        tokensBuilder.idToken(idToken);

        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getTokenSettings().enableRefreshTokens()) {
            refreshToken = OAuth2TokenIssuerUtil.issueRefreshToken(registeredClient.getTokenSettings().refreshTokenTimeToLive());
            tokensBuilder.refreshToken(refreshToken);
        }

        OAuth2Tokens tokens = tokensBuilder.build();
        authorization = OAuth2Authorization.from(authorization)
                .tokens(tokens)
                .attribute(OAuth2AuthorizationAttributeNames.ACCESS_TOKEN_ATTRIBUTES, jwt)
                .build();

        authorization = OAuth2AuthenticationProviderUtils.invalidate(authorization, authorizationCode);

        this.authorizationService.save(authorization);
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, idToken, refreshToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
