package io.futakotome.tenantService.domain.saas.application;

import io.futakotome.tenantService.domain.saas.core.exception.SaasSaveException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalSaasExceptionHandler {

    @ExceptionHandler(value = SaasSaveException.class)
    public ResponseEntity<String> saasSaveExceptionHandler(SaasSaveException exception) {
        return new ResponseEntity<>(exception.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
