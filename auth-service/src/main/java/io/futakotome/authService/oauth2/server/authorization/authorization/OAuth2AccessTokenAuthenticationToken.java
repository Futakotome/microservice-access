package io.futakotome.authService.oauth2.server.authorization.authorization;

import io.futakotome.authService.oauth2.server.authorization.Version;
import io.futakotome.authService.oauth2.server.authorization.client.RegisteredClient;
import io.futakotome.authService.oauth2.server.authorization.token.OAuth2RefreshToken;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.util.Assert;

import java.util.Collections;

/**
 * 颁发access token、id token和refresh token (可选)
 *
 * @author futakotome
 */
public class OAuth2AccessTokenAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
    private final RegisteredClient registeredClient;
    private final Authentication clientPrincipal;
    private final OAuth2AccessToken accessToken;
    private final OAuth2RefreshToken refreshToken;
    private final OidcIdToken idToken;

    public OAuth2AccessTokenAuthenticationToken(RegisteredClient registeredClient, Authentication clientPrincipal, OAuth2AccessToken accessToken) {
        this(registeredClient, clientPrincipal, accessToken, null, null);//todo id token先null
    }

    public OAuth2AccessTokenAuthenticationToken(RegisteredClient registeredClient, Authentication clientPrincipal,
                                                OAuth2AccessToken accessToken, OidcIdToken idToken, @Nullable OAuth2RefreshToken refreshToken) {
        super(Collections.emptyList());
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
        Assert.notNull(accessToken, "accessToken cannot be null");
        this.idToken = idToken;
        this.registeredClient = registeredClient;
        this.clientPrincipal = clientPrincipal;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public OidcIdToken getIdToken() {
        return idToken;
    }

    public RegisteredClient getRegisteredClient() {
        return registeredClient;
    }

    public OAuth2AccessToken getAccessToken() {
        return accessToken;
    }

    public OAuth2RefreshToken getRefreshToken() {
        return refreshToken;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.clientPrincipal;
    }
}
