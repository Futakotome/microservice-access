package io.futakotome.tenantService.domain.saas.core.ports.incoming;

import io.futakotome.tenantService.domain.saas.core.exception.SaasSaveException;
import io.futakotome.tenantService.domain.saas.core.model.Saas;
import io.futakotome.tenantService.domain.saas.core.model.SaasSaveCommand;

public interface SaasStore {
    Saas saveBy(SaasSaveCommand saveCommand) throws SaasSaveException;
}
