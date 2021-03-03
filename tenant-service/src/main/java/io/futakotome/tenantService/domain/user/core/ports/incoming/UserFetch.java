package io.futakotome.tenantService.domain.user.core.ports.incoming;

import io.futakotome.tenantService.domain.user.core.exception.UserNotFoundException;
import io.futakotome.tenantService.domain.user.core.model.User;

public interface UserFetch {
    User findBy(String id) throws UserNotFoundException;
}
