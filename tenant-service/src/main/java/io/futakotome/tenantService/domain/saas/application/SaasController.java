package io.futakotome.tenantService.domain.saas.application;

import io.futakotome.tenantService.domain.saas.core.exception.SaasSaveException;
import io.futakotome.tenantService.domain.saas.core.model.Saas;
import io.futakotome.tenantService.domain.saas.core.model.SaasSaveCommand;
import io.futakotome.tenantService.domain.saas.core.ports.incoming.SaasStore;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/saas")
@RequiredArgsConstructor
public class SaasController {

    private final SaasStore saasStore;

    @PostMapping("/")
    public ResponseEntity<Saas> save(@RequestBody SaasSaveCommand command) {
        return Optional.of(ResponseEntity.ok(saasStore.saveBy(command)))
                .orElseThrow(() -> new SaasSaveException("服务保存失败:" + command.getName()));
    }
}
