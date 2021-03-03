package io.futakotome.tenantService.domain.user.core.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
public class UserSaveCommand {
    private String username;
    private String password;
    private String realName;
    private String email;
    private String phone;
    private Sex sex;
    private Integer age;

}
