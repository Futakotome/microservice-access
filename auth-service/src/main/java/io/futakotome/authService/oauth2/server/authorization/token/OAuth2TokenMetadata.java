package io.futakotome.authService.oauth2.server.authorization.token;

import io.futakotome.authService.oauth2.server.authorization.Version;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * 和OAuth2 token关联的元数据
 *
 * @author futakotome
 * @see OAuth2Tokens
 */
public class OAuth2TokenMetadata implements Serializable {
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
    protected static final String TOKEN_METADATA_BASE = "token.metadata.";

    //todo metadata 目前只有一个属性
    public static final String INVALIDATED = TOKEN_METADATA_BASE.concat("invalidated");

    private final Map<String, Object> metadata;

    protected OAuth2TokenMetadata(Map<String, Object> metadata) {
        this.metadata = Collections.unmodifiableMap(new HashMap<>(metadata));
    }

    public boolean isInvalidated() {
        return getMetadata(INVALIDATED);
    }

    @SuppressWarnings("unchecked")
    public <T> T getMetadata(String name) {
        Assert.hasText(name, "name cannot be empty");
        return (T) this.metadata.get(name);
    }

    public Map<String, Object> getMetadata() {
        return this.metadata;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OAuth2TokenMetadata that = (OAuth2TokenMetadata) o;
        return Objects.equals(metadata, that.metadata);
    }

    @Override
    public int hashCode() {

        return Objects.hash(metadata);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder implements Serializable {
        private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
        private final Map<String, Object> metadata = defaultMetadata();

        protected Builder() {
        }

        public Builder invalidated() {
            metadata(INVALIDATED, true);
            return this;
        }

        public Builder metadata(String name, Object value) {
            Assert.hasText(name, "name cannot be empty");
            Assert.notNull(value, "value cannot be null");
            this.metadata.put(name, value);
            return this;
        }

        public Builder metadata(Consumer<Map<String, Object>> metadataConsumer) {
            metadataConsumer.accept(this.metadata);
            return this;
        }

        public OAuth2TokenMetadata build() {
            return new OAuth2TokenMetadata(this.metadata);
        }

        protected static Map<String, Object> defaultMetadata() {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put(INVALIDATED, false);
            return metadata;
        }
    }
}
