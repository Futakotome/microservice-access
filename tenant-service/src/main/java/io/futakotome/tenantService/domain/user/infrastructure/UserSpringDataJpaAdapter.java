package io.futakotome.tenantService.domain.user.infrastructure;

import io.futakotome.tenantService.domain.user.core.model.User;
import io.futakotome.tenantService.domain.user.core.ports.outgoing.UserRepository;
import io.futakotome.tenantService.domain.user.infrastructure.data.UserSpringDataJpaRepository;
import lombok.RequiredArgsConstructor;

import java.util.Optional;

@RequiredArgsConstructor
public class UserSpringDataJpaAdapter implements UserRepository {

    private final UserSpringDataJpaRepository userRepository;

    @Override
    public User save(User user) {
        return userRepository.save(user);
    }

    @Override
    public Optional<User> findBy(String id) {
        return userRepository.findById(id);
    }
}
