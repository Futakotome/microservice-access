package io.futakotome.authService.oauth2.server.authorization.authorization;

import io.futakotome.authService.oauth2.server.authorization.OAuth2Authorization;
import io.futakotome.authService.oauth2.server.authorization.OAuth2AuthorizationService;
import io.futakotome.authService.oauth2.server.authorization.TokenType;
import io.futakotome.authService.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class OAuth2TokenRevocationAuthenticationProvider implements AuthenticationProvider {
    private final OAuth2AuthorizationService authorizationService;

    public OAuth2TokenRevocationAuthenticationProvider(OAuth2AuthorizationService authorizationService) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        this.authorizationService = authorizationService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2TokenRevocationAuthenticationToken tokenRevocationAuthentication = (OAuth2TokenRevocationAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(tokenRevocationAuthentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) tokenRevocationAuthentication.getPrincipal();
        }
        if (clientPrincipal == null || !clientPrincipal.isAuthenticated()) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
        }
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        TokenType tokenType = null;
        String tokenTypeHint = tokenRevocationAuthentication.getTokenTypeHint();
        if (StringUtils.hasText(tokenTypeHint)) {
            if (TokenType.REFRESH_TOKEN.getValue().equals(tokenTypeHint)) {
                tokenType = TokenType.REFRESH_TOKEN;
            } else if (TokenType.ACCESS_TOKEN.getValue().equals(tokenTypeHint)) {
                tokenType = TokenType.ACCESS_TOKEN;
            } else {
                //todo 应该自定义 错误类型
                throw new OAuth2AuthenticationException(new OAuth2Error("unsupported_token_type"));
            }
        }
        OAuth2Authorization authorization = this.authorizationService.findByToken(tokenRevocationAuthentication.getToken(), tokenType);
        if (authorization == null) {
            // todo 应该返回验证请求当找不到token的时候
            return tokenRevocationAuthentication;
        }
        if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
        }
        AbstractOAuth2Token token = authorization.getTokens().getToken(tokenRevocationAuthentication.getToken());
        authorization = OAuth2AuthenticationProviderUtils.invalidate(authorization, token);
        this.authorizationService.save(authorization);
        return new OAuth2TokenRevocationAuthenticationToken(token, clientPrincipal);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2TokenRevocationAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
