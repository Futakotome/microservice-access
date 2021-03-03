package io.futakotome.authService.crypto.keys;

import org.springframework.lang.Nullable;

import java.util.Set;

public interface KeyManager {
    @Nullable
    ManagedKey findByKeyId(String keyId);

    Set<ManagedKey> findByAlgorithm(String algorithm);

    Set<ManagedKey> getKeys();
}
