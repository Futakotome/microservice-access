package io.futakotome.authService.crypto.keys;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class StaticKeyGeneratingKeyManager implements KeyManager {

    private final Map<String, ManagedKey> keys;

    public StaticKeyGeneratingKeyManager() {
        this.keys = Collections.unmodifiableMap(new HashMap<>(generateKeys()));
    }

    @Nullable
    @Override
    public ManagedKey findByKeyId(String keyId) {
        Assert.hasText(keyId, "keyId cannot be empty");
        return this.keys.get(keyId);
    }

    @Override
    public Set<ManagedKey> findByAlgorithm(String algorithm) {
        Assert.hasText(algorithm, "algorithm cannot be empty");
        return this.keys.values().stream()
                .filter(managedKey -> managedKey.getAlgorithm().equals(algorithm))
                .collect(Collectors.toSet());
    }

    @Override
    public Set<ManagedKey> getKeys() {
        return new HashSet<>(this.keys.values());
    }


    private static Map<String, ManagedKey> generateKeys() {
        KeyPair rsaKeyPair = KeyGeneratorUtils.generateRsaKey();
        ManagedKey rsaManagedKey = ManagedKey.withAsymmetricKey(rsaKeyPair.getPublic(), rsaKeyPair.getPrivate())
                .keyId(UUID.randomUUID().toString())
                .activatedOn(Instant.now())
                .build();

        SecretKey hmacKey = KeyGeneratorUtils.generateSecretKey();
        ManagedKey secretManagedKey = ManagedKey.withSymmetricKey(hmacKey)
                .keyId(UUID.randomUUID().toString())
                .activatedOn(Instant.now())
                .build();

        return Stream.of(rsaManagedKey, secretManagedKey)
                .collect(Collectors.toMap(ManagedKey::getKeyId, v -> v));
    }
}
