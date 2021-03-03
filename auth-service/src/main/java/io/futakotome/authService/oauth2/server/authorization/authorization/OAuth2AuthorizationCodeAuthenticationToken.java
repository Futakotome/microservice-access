package io.futakotome.authService.oauth2.server.authorization.authorization;

import io.futakotome.authService.oauth2.server.authorization.Version;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.Map;

public class OAuth2AuthorizationCodeAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
    private final String code;
    private final Authentication clientPrincipal;
    private final String redirectUri;
    private final Map<String, Object> additionalParameters;

    public OAuth2AuthorizationCodeAuthenticationToken(String code,
                                                      Authentication clientPrincipal,
                                                      @Nullable String redirectUri,
                                                      @Nullable Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        Assert.hasText(code, "code cannot be empty");
        Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
        this.code = code;
        this.clientPrincipal = clientPrincipal;
        this.redirectUri = redirectUri;
        this.additionalParameters = Collections.unmodifiableMap(additionalParameters != null ? additionalParameters : Collections.emptyMap());
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.clientPrincipal;
    }

    public String getCode() {
        return code;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }
}
