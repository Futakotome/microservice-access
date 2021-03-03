package io.futakotome.tenantService.domain.user.core.exception;

public class UserSaveException extends RuntimeException {
    public UserSaveException(String message) {
        super(message);
    }
}
