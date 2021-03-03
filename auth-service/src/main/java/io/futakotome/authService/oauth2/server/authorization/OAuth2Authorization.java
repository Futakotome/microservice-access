package io.futakotome.authService.oauth2.server.authorization;

import io.futakotome.authService.oauth2.server.authorization.client.RegisteredClient;
import io.futakotome.authService.oauth2.server.authorization.token.OAuth2Tokens;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * oauth2验证类,有oauth2相关的各种token和属性
 *
 * @author futakotome
 * @see RegisteredClient
 * @see OAuth2Tokens
 */
public class OAuth2Authorization implements Serializable {
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
    private String registeredClientId;
    private String principalName;
    private OAuth2Tokens tokens;

    private OAuth2AccessToken accessToken;

    private Map<String, Object> attributes;

    public OAuth2Authorization() {
    }

    public String getRegisteredClientId() {
        return this.registeredClientId;
    }

    public String getPrincipalName() {
        return this.principalName;
    }

    public OAuth2Tokens getTokens() {
        return this.tokens;
    }

    public OAuth2AccessToken getAccessToken() {
        return getTokens().getAccessToken();
    }

    public Map<String, Object> getAttributes() {
        return this.attributes;
    }

    @SuppressWarnings("unchecked")
    public <T> T getAttribute(String name) {
        Assert.hasText(name, "name cannot be empty");
        return (T) this.attributes.get(name);
    }

    @Override
    public String toString() {
        return "OAuth2Authorization{" +
                "registeredClientId='" + registeredClientId + '\'' +
                ", principalName='" + principalName + '\'' +
                ", tokens=" + tokens +
                ", accessToken=" + accessToken +
                ", attributes=" + attributes +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OAuth2Authorization that = (OAuth2Authorization) o;
        return Objects.equals(registeredClientId, that.registeredClientId) &&
                Objects.equals(principalName, that.principalName) &&
                Objects.equals(tokens, that.tokens) &&
                Objects.equals(attributes, that.attributes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(registeredClientId, principalName, tokens, attributes);
    }

    public static Builder withRegisteredClient(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        return new Builder(registeredClient.getId());
    }

    public static Builder from(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        return new Builder(authorization.getRegisteredClientId())
                .principalName(authorization.getPrincipalName())
                .tokens(OAuth2Tokens.from(authorization.getTokens()).build())
                .attributes(attrs -> attrs.putAll(authorization.getAttributes()));
    }

    public static class Builder implements Serializable {
        private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
        private String registeredClientId;
        private String principalName;
        private OAuth2Tokens tokens;

        private OAuth2AccessToken accessToken;

        private Map<String, Object> attributes = new HashMap<>();

        protected Builder(String registeredClientId) {
            this.registeredClientId = registeredClientId;
        }

        public Builder principalName(String principalName) {
            this.principalName = principalName;
            return this;
        }

        public Builder tokens(OAuth2Tokens tokens) {
            this.tokens = tokens;
            return this;
        }

        public Builder accessToken(OAuth2AccessToken accessToken) {
            this.accessToken = accessToken;
            return this;
        }

        public Builder attribute(String name, Object value) {
            Assert.hasText(name, "name cannot be empty");
            Assert.notNull(value, "value cannot be null");
            this.attributes.put(name, value);
            return this;
        }

        public Builder attributes(Consumer<Map<String, Object>> attributesConsumer) {
            attributesConsumer.accept(this.attributes);
            return this;
        }

        public OAuth2Authorization build() {
            Assert.hasText(this.principalName, "principalName cannot be empty");

            OAuth2Authorization authorization = new OAuth2Authorization();
            authorization.registeredClientId = this.registeredClientId;
            authorization.principalName = this.principalName;
            if (this.tokens == null) {
                OAuth2Tokens.Builder builder = OAuth2Tokens.builder();
                if (this.accessToken != null) {
                    builder.accessToken(this.accessToken);
                }
                this.tokens = builder.build();
            }
            authorization.tokens = this.tokens;
            authorization.attributes = Collections.unmodifiableMap(this.attributes);
            return authorization;
        }
    }
}
