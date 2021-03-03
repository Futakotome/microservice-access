package io.futakotome.tenantService.domain.saas.core.exception;

public class SaasSaveException extends RuntimeException {
    public SaasSaveException(String message) {
        super(message);
    }
}
