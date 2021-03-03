package io.futakotome.tenantService.domain.user.core.ports.incoming;

import io.futakotome.tenantService.domain.user.core.exception.UserSaveException;
import io.futakotome.tenantService.domain.user.core.model.User;
import io.futakotome.tenantService.domain.user.core.model.UserSaveCommand;

public interface UserStore {
    User saveBy(UserSaveCommand saveCommand) throws UserSaveException;
}
