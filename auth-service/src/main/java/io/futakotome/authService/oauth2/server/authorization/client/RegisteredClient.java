package io.futakotome.authService.oauth2.server.authorization.client;

import io.futakotome.authService.oauth2.server.authorization.Version;
import io.futakotome.authService.oauth2.server.authorization.config.ClientSettings;
import io.futakotome.authService.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Consumer;

/**
 * oauth2 client
 *
 * @author futakotome
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-2">Section 2 Client Registration</a>
 */
public class RegisteredClient implements Serializable {
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
    private String id;
    private String clientId;
    private String clientSecret;
    private Set<ClientAuthenticationMethod> clientAuthenticationMethods;
    private Set<AuthorizationGrantType> authorizationGrantTypes;
    private Set<String> redirectUris;
    private Set<String> scopes;
    private ClientSettings clientSettings;
    private TokenSettings tokenSettings;

    public RegisteredClient() {
    }

    public String getId() {
        return id;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public Set<ClientAuthenticationMethod> getClientAuthenticationMethods() {
        return clientAuthenticationMethods;
    }

    public Set<AuthorizationGrantType> getAuthorizationGrantTypes() {
        return authorizationGrantTypes;
    }

    public Set<String> getRedirectUris() {
        return redirectUris;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public ClientSettings getClientSettings() {
        return clientSettings;
    }

    public TokenSettings getTokenSettings() {
        return tokenSettings;
    }

    @Override
    public String toString() {
        return "RegisteredClient{" +
                "id='" + id + '\'' +
                ", clientId='" + clientId + '\'' +
                ", clientSecret='" + clientSecret + '\'' +
                ", clientAuthenticationMethods=" + clientAuthenticationMethods +
                ", authorizationGrantTypes=" + authorizationGrantTypes +
                ", redirectUris=" + redirectUris +
                ", scopes=" + scopes +
                ", clientSettings=" + clientSettings +
                ", tokenSettings=" + tokenSettings +
                '}';
    }

    public static Builder withId(String id) {
        Assert.hasText(id, "id cannot be empty");
        return new Builder(id);
    }

    public static Builder withRegisteredClient(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        return new Builder(registeredClient);
    }

    public static class Builder implements Serializable {
        private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
        private String id;
        private String clientId;
        private String clientSecret;
        private Set<ClientAuthenticationMethod> clientAuthenticationMethods = new LinkedHashSet<>();
        private Set<AuthorizationGrantType> authorizationGrantTypes = new LinkedHashSet<>();
        private Set<String> redirectUris = new LinkedHashSet<>();
        private Set<String> scopes = new LinkedHashSet<>();
        private ClientSettings clientSettings = new ClientSettings();
        private TokenSettings tokenSettings = new TokenSettings();

        protected Builder(String id) {
            this.id = id;
        }

        protected Builder(RegisteredClient registeredClient) {
            this.id = registeredClient.id;
            this.clientId = registeredClient.clientId;
            this.clientSecret = registeredClient.clientSecret;
            if (!CollectionUtils.isEmpty(registeredClient.clientAuthenticationMethods)) {
                this.clientAuthenticationMethods.addAll(registeredClient.clientAuthenticationMethods);
            }
            if (!CollectionUtils.isEmpty(registeredClient.authorizationGrantTypes)) {
                this.authorizationGrantTypes.addAll(registeredClient.authorizationGrantTypes);
            }
            if (!CollectionUtils.isEmpty(registeredClient.redirectUris)) {
                this.redirectUris.addAll(registeredClient.redirectUris);
            }
            if (!CollectionUtils.isEmpty(registeredClient.scopes)) {
                this.scopes.addAll(registeredClient.scopes);
            }
            this.clientSettings = new ClientSettings(registeredClient.clientSettings.settings());
            this.tokenSettings = new TokenSettings(registeredClient.tokenSettings.settings());
        }

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public Builder clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
            this.clientAuthenticationMethods.add(clientAuthenticationMethod);
            return this;
        }

        public Builder clientAuthenticationMethods(
                Consumer<Set<ClientAuthenticationMethod>> clientAuthenticationMethodsConsumer) {
            clientAuthenticationMethodsConsumer.accept(this.clientAuthenticationMethods);
            return this;
        }

        public Builder authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
            this.authorizationGrantTypes.add(authorizationGrantType);
            return this;
        }

        public Builder authorizationGrantTypes(Consumer<Set<AuthorizationGrantType>> authorizationGrantTypesConsumer) {
            authorizationGrantTypesConsumer.accept(this.authorizationGrantTypes);
            return this;
        }

        public Builder redirectUri(String redirectUri) {
            this.redirectUris.add(redirectUri);
            return this;
        }

        public Builder redirectUris(Consumer<Set<String>> redirectUrisConsumer) {
            redirectUrisConsumer.accept(this.redirectUris);
            return this;
        }

        public Builder scope(String scope) {
            this.scopes.add(scope);
            return this;
        }

        public Builder scopes(Consumer<Set<String>> scopesConsumer) {
            scopesConsumer.accept(this.scopes);
            return this;
        }

        public Builder clientSettings(Consumer<ClientSettings> clientSettingsConsumer) {
            clientSettingsConsumer.accept(this.clientSettings);
            return this;
        }

        public Builder tokenSettings(Consumer<TokenSettings> tokenSettingsConsumer) {
            tokenSettingsConsumer.accept(this.tokenSettings);
            return this;
        }

        public RegisteredClient build() {
            Assert.hasText(this.clientId, "clientId cannot be empty");
            Assert.notEmpty(this.authorizationGrantTypes, "authorizationGrantTypes cannot be empty");
            if (this.authorizationGrantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
                Assert.notEmpty(this.redirectUris, "redirectUris cannot be empty");
            }
            if (CollectionUtils.isEmpty(this.clientAuthenticationMethods)) {
                this.clientAuthenticationMethods.add(ClientAuthenticationMethod.BASIC);
            }
            validateScopes();
            validateRedirectUris();
            return create();
        }

        private RegisteredClient create() {
            RegisteredClient registeredClient = new RegisteredClient();

            registeredClient.id = this.id;
            registeredClient.clientId = this.clientId;
            registeredClient.clientSecret = this.clientSecret;
            registeredClient.clientAuthenticationMethods =
                    Collections.unmodifiableSet(this.clientAuthenticationMethods);
            registeredClient.authorizationGrantTypes = Collections.unmodifiableSet(this.authorizationGrantTypes);
            registeredClient.redirectUris = Collections.unmodifiableSet(this.redirectUris);
            registeredClient.scopes = Collections.unmodifiableSet(this.scopes);
            registeredClient.clientSettings = this.clientSettings;
            registeredClient.tokenSettings = this.tokenSettings;

            return registeredClient;
        }

        private void validateScopes() {
            if (CollectionUtils.isEmpty(this.scopes)) {
                return;
            }

            for (String scope : this.scopes) {
                Assert.isTrue(validateScope(scope), "scope \"" + scope + "\" contains invalid characters");
            }
        }

        private static boolean validateScope(String scope) {
            return scope == null ||
                    scope.chars().allMatch(c -> withinTheRangeOf(c, 0x21, 0x21) ||
                            withinTheRangeOf(c, 0x23, 0x5B) ||
                            withinTheRangeOf(c, 0x5D, 0x7E));
        }

        private static boolean withinTheRangeOf(int c, int min, int max) {
            return c >= min && c <= max;
        }

        private void validateRedirectUris() {
            if (CollectionUtils.isEmpty(this.redirectUris)) {
                return;
            }

            for (String redirectUri : redirectUris) {
                Assert.isTrue(validateRedirectUri(redirectUri),
                        "redirect_uri \"" + redirectUri + "\" is not a valid redirect URI or contains fragment");
            }
        }

        private static boolean validateRedirectUri(String redirectUri) {
            try {
                URI validRedirectUri = new URI(redirectUri);
                return validRedirectUri.getFragment() == null;
            } catch (URISyntaxException ex) {
                return false;
            }
        }
    }
}
