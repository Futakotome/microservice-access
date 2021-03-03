package io.futakotome.tenantService.infrastructure.config.domain;

import io.futakotome.tenantService.domain.saas.core.ports.SaasFacade;
import io.futakotome.tenantService.domain.saas.core.ports.incoming.SaasStore;
import io.futakotome.tenantService.domain.saas.core.ports.outgoing.SaasRepository;
import io.futakotome.tenantService.domain.saas.infrastructure.SaasSpringDataJpaAdapter;
import io.futakotome.tenantService.domain.saas.infrastructure.data.SaasSpringDataJpaRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SaasDomainConfig {
    @Bean
    public SaasRepository saasRepository(SaasSpringDataJpaRepository jpaRepository) {
        return new SaasSpringDataJpaAdapter(jpaRepository);
    }

    @Bean
    public SaasStore saasStore(SaasRepository saasRepository) {
        return new SaasFacade(saasRepository);
    }
}
