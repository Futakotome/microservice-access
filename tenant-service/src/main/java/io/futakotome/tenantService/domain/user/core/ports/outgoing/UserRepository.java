package io.futakotome.tenantService.domain.user.core.ports.outgoing;

import io.futakotome.tenantService.domain.user.core.model.User;

import java.util.Optional;

public interface UserRepository {
    User save(User user);

    Optional<User> findBy(String id);
}
