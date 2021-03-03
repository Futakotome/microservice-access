package io.futakotome.authService.crypto.keys;

import io.futakotome.authService.oauth2.server.authorization.Version;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.time.Instant;
import java.util.Objects;

/**
 * {@link KeyManager} 管理的{@code java.Security.Key}
 *
 * @see KeyManager
 */
public final class ManagedKey implements Serializable {
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
    private Key key;
    private PublicKey publicKey;
    private String keyId;
    private Instant activatedOn;
    private Instant deactivatedOn;

    private ManagedKey() {
    }

    public boolean isSymmetric() {
        return Security.class.isAssignableFrom(this.key.getClass());
    }

    public boolean isAsymmetric() {
        return PrivateKey.class.isAssignableFrom(this.key.getClass());
    }

    /**
     * 返回key
     *
     * @param <T> {@code java.Security.Key}类型的类
     * @return {@code java.Security.Key}类型的类
     */
    @SuppressWarnings("unchecked")
    public <T extends Key> T getKey() {
        return (T) this.key;
    }

    @Nullable
    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public String getKeyId() {
        return this.keyId;
    }

    public Instant getActivatedOn() {
        return this.activatedOn;
    }

    @Nullable
    public Instant getDeactivatedOn() {
        return this.deactivatedOn;
    }

    public boolean isActive() {
        return getDeactivatedOn() == null;
    }

    public String getAlgorithm() {
        return this.key.getAlgorithm();
    }


    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        ManagedKey that = (ManagedKey) obj;
        return Objects.equals(this.keyId, that.keyId);
    }

    public static Builder withSymmetricKey(SecretKey secretKey) {
        return new Builder(secretKey);
    }

    public static Builder withAsymmetricKey(PublicKey publicKey, PrivateKey privateKey) {
        return new Builder(publicKey, privateKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.keyId);
    }

    public static class Builder {
        private Key key;
        private PublicKey publicKey;
        private String keyId;
        private Instant activatedOn;
        private Instant deactivatedOn;

        public Builder(SecretKey secretKey) {
            Assert.notNull(secretKey, "secretKey must not be null");
            this.key = secretKey;
        }

        public Builder(PublicKey publicKey, PrivateKey privateKey) {
            Assert.notNull(publicKey, "publicKey cannot be null");
            Assert.notNull(privateKey, "privateKey cannot be null");
            this.key = privateKey;
            this.publicKey = publicKey;
        }

        public Builder keyId(String keyId) {
            this.keyId = keyId;
            return this;
        }

        public Builder activatedOn(Instant activatedOn) {
            this.activatedOn = activatedOn;
            return this;
        }

        public Builder deactivatedOn(Instant deactivatedOn) {
            this.deactivatedOn = deactivatedOn;
            return this;
        }

        public ManagedKey build() {
            Assert.hasText(this.keyId, "keyId cannot be empty");
            Assert.notNull(this.activatedOn, "activatedOn cannot be null");

            ManagedKey managedKey = new ManagedKey();
            managedKey.key = this.key;
            managedKey.publicKey = this.publicKey;
            managedKey.keyId = this.keyId;
            managedKey.activatedOn = this.activatedOn;
            managedKey.deactivatedOn = this.deactivatedOn;
            return managedKey;
        }
    }
}
