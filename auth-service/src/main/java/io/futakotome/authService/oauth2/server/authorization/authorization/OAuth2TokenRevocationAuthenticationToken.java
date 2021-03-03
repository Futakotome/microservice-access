package io.futakotome.authService.oauth2.server.authorization.authorization;

import io.futakotome.authService.oauth2.server.authorization.Version;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.util.Assert;

import java.util.Collections;

public class OAuth2TokenRevocationAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
    private final String token;
    private final Authentication clientPrincipal;
    private final String tokenTypeHint;

    public OAuth2TokenRevocationAuthenticationToken(String token, Authentication clientPrincipal, @Nullable String tokenTypeHint) {
        super(Collections.emptyList());
        Assert.hasText(token, "token cannot be empty");
        Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
        this.token = token;
        this.clientPrincipal = clientPrincipal;
        this.tokenTypeHint = tokenTypeHint;
    }

    public OAuth2TokenRevocationAuthenticationToken(AbstractOAuth2Token revokedToken, Authentication clientPrincipal) {
        super(Collections.emptyList());
        Assert.notNull(revokedToken, "revokedToken cannot be null");
        Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
        this.token = revokedToken.getTokenValue();
        this.clientPrincipal = clientPrincipal;
        this.tokenTypeHint = null;
        setAuthenticated(true);
    }


    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.clientPrincipal;
    }

    public String getToken() {
        return token;
    }

    public String getTokenTypeHint() {
        return tokenTypeHint;
    }
}
