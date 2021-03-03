package io.futakotome.tenantService.domain.saas.core.ports;

import io.futakotome.tenantService.domain.saas.core.model.Saas;
import io.futakotome.tenantService.domain.saas.core.model.SaasSaveCommand;
import io.futakotome.tenantService.domain.saas.core.ports.incoming.SaasStore;
import io.futakotome.tenantService.domain.saas.core.ports.outgoing.SaasRepository;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class SaasFacade implements SaasStore {

    private final SaasRepository saasRepository;

    @Override
    public Saas saveBy(SaasSaveCommand saveCommand) {
        return null;
    }
}
