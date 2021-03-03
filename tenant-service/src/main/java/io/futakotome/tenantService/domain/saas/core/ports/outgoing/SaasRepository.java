package io.futakotome.tenantService.domain.saas.core.ports.outgoing;

import io.futakotome.tenantService.domain.saas.core.model.Saas;

public interface SaasRepository {
    Saas save(Saas saas);
}
