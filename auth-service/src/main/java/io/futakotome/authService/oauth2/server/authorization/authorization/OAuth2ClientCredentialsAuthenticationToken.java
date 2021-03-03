package io.futakotome.authService.oauth2.server.authorization.authorization;

import io.futakotome.authService.oauth2.server.authorization.Version;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public class OAuth2ClientCredentialsAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
    private final Authentication clientPrincipal;
    private final Set<String> scopes;

    public OAuth2ClientCredentialsAuthenticationToken(Authentication clientPrincipal) {
        this(clientPrincipal, Collections.emptySet());
    }

    public OAuth2ClientCredentialsAuthenticationToken(Authentication clientPrincipal, Set<String> scopes) {
        super(Collections.emptyList());
        Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
        Assert.notNull(scopes, "scopes cannot be null");
        this.clientPrincipal = clientPrincipal;
        this.scopes = Collections.unmodifiableSet(new LinkedHashSet<>(scopes));
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.clientPrincipal;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
