package io.futakotome.tenantService.domain.saas.infrastructure.data;

import io.futakotome.tenantService.domain.saas.core.model.Saas;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SaasSpringDataJpaRepository extends JpaRepository<Saas, String> {
}
