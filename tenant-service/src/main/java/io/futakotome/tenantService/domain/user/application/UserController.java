package io.futakotome.tenantService.domain.user.application;

import io.futakotome.tenantService.domain.user.core.exception.UserNotFoundException;
import io.futakotome.tenantService.domain.user.core.exception.UserSaveException;
import io.futakotome.tenantService.domain.user.core.model.User;
import io.futakotome.tenantService.domain.user.core.model.UserSaveCommand;
import io.futakotome.tenantService.domain.user.core.ports.incoming.UserFetch;
import io.futakotome.tenantService.domain.user.core.ports.incoming.UserStore;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserStore userStore;
    private final UserFetch userFetch;

    @PostMapping("/")
    public ResponseEntity<User> save(@RequestBody UserSaveCommand saveCommand) {
        return Optional.of(ResponseEntity.ok(userStore.saveBy(saveCommand)))
                .orElseThrow(() -> new UserSaveException("用户保存失败:" + saveCommand.getUsername()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<User> findById(@PathVariable(name = "id") String id) {
        return Optional.of(ResponseEntity.ok(userFetch.findBy(id)))
                .orElseThrow(() -> new UserNotFoundException("用户不存在:" + id));
    }
}
