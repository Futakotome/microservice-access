package io.futakotome.tenantService.domain.saas.infrastructure;

import io.futakotome.tenantService.domain.saas.core.model.Saas;
import io.futakotome.tenantService.domain.saas.core.ports.outgoing.SaasRepository;
import io.futakotome.tenantService.domain.saas.infrastructure.data.SaasSpringDataJpaRepository;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class SaasSpringDataJpaAdapter implements SaasRepository {

    private final SaasSpringDataJpaRepository saasRepository;

    @Override
    public Saas save(Saas saas) {
        return null;
    }
}
