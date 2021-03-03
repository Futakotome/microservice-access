package io.futakotome.tenantService.domain.user.application;

import io.futakotome.tenantService.domain.user.core.exception.UserNotFoundException;
import io.futakotome.tenantService.domain.user.core.exception.UserSaveException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalUserExceptionHandler {

    @ExceptionHandler(value = UserSaveException.class)
    public ResponseEntity<String> userSaveExceptionHandler(UserSaveException exception) {
        return new ResponseEntity<>(exception.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(value = UserNotFoundException.class)
    public ResponseEntity<String> userNotFoundExceptionHandler(UserNotFoundException exception) {
        return new ResponseEntity<>(exception.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
