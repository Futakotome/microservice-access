package io.futakotome.authService.oauth2.server.authorization.authorization;

import io.futakotome.authService.oauth2.server.authorization.Version;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.Set;

public class OAuth2RefreshTokenAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
    private final String refreshToken;
    private final Authentication clientPrincipal;
    private final Set<String> scopes;

    public OAuth2RefreshTokenAuthenticationToken(String refreshToken, Authentication clientPrincipal) {
        this(refreshToken, clientPrincipal, Collections.emptySet());
    }

    public OAuth2RefreshTokenAuthenticationToken(String refreshToken, Authentication clientPrincipal,
                                                 Set<String> scopes) {
        super(Collections.emptySet());
        Assert.hasText(refreshToken, "refreshToken cannot be empty");
        Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
        Assert.notNull(scopes, "scopes cannot be null");
        this.refreshToken = refreshToken;
        this.clientPrincipal = clientPrincipal;
        this.scopes = scopes;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.clientPrincipal;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
