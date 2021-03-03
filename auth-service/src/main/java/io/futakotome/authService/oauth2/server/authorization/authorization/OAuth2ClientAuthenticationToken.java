package io.futakotome.authService.oauth2.server.authorization.authorization;

import io.futakotome.authService.oauth2.server.authorization.Version;
import io.futakotome.authService.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.Map;

public class OAuth2ClientAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
    private String clientId;
    private String clientSecret;
    private Map<String, Object> additionalParameters;
    private RegisteredClient registeredClient;

    public OAuth2ClientAuthenticationToken(String clientId, String clientSecret,
                                           @Nullable Map<String, Object> additionalParameters) {
        this(clientId, additionalParameters);
        Assert.hasText(clientSecret, "clientSecret cannot be empty");
        this.clientSecret = clientSecret;
    }

    public OAuth2ClientAuthenticationToken(String clientId,
                                           @Nullable Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        Assert.hasText(clientId, "clientId cannot be empty");
        this.clientId = clientId;
        this.additionalParameters = additionalParameters != null ?
                Collections.unmodifiableMap(additionalParameters) : null;
    }

    public OAuth2ClientAuthenticationToken(RegisteredClient registeredClient) {
        super(Collections.emptyList());
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        this.registeredClient = registeredClient;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.clientSecret;
    }

    @Override
    public Object getPrincipal() {
        return this.registeredClient != null ? this.registeredClient.getClientId() : this.clientId;
    }

    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }

    public RegisteredClient getRegisteredClient() {
        return registeredClient;
    }
}
