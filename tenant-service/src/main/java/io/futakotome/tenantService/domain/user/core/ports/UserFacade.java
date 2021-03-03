package io.futakotome.tenantService.domain.user.core.ports;

import io.futakotome.tenantService.domain.user.core.exception.UserNotFoundException;
import io.futakotome.tenantService.domain.user.core.exception.UserSaveException;
import io.futakotome.tenantService.domain.user.core.model.User;
import io.futakotome.tenantService.domain.user.core.model.UserSaveCommand;
import io.futakotome.tenantService.domain.user.core.ports.incoming.UserFetch;
import io.futakotome.tenantService.domain.user.core.ports.incoming.UserStore;
import io.futakotome.tenantService.domain.user.core.ports.outgoing.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
public class UserFacade implements UserStore, UserFetch {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public User saveBy(UserSaveCommand saveCommand) throws UserSaveException {
        User saved = userRepository.save(User.createBy(saveCommand));
        if (saved.getId() != null) {
            return saved;
        }
        throw new UserSaveException("用户保存失败:" + saveCommand.getUsername());
    }

    @Override
    public User findBy(String id) throws UserNotFoundException {
        return userRepository.findBy(id)
                .orElseThrow(() -> new UserNotFoundException("用户不存在:" + id));
    }
}
