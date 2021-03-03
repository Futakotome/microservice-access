package io.futakotome.tenantService.domain.user.infrastructure.data;

import io.futakotome.tenantService.domain.user.core.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserSpringDataJpaRepository extends JpaRepository<User, String> {
}
