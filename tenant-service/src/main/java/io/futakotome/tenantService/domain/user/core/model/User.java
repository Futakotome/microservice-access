package io.futakotome.tenantService.domain.user.core.model;

import io.futakotome.tenantService.domain.DomainBase;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.persistence.*;

@Getter
@Setter
@Entity(name = "t_user")
public class User extends DomainBase<User> {

    @Column(name = "user_name", nullable = false)
    private String username;

    @Column(name = "password", nullable = false)
    private String password;

    @Embedded
    @AttributeOverrides({
            @AttributeOverride(name = "realName", column = @Column(name = "real_name")),
            @AttributeOverride(name = "email", column = @Column(name = "email")),
            @AttributeOverride(name = "phone", column = @Column(name = "phone")),
            @AttributeOverride(name = "sex", column = @Column(name = "sex")),
            @AttributeOverride(name = "age", column = @Column(name = "age"))
    })
    private UserInfo userInfo;

    public static User createBy(UserSaveCommand saveCommand) {
        User user = new User();
        //todo can add some validation
        user.setUsername(saveCommand.getUsername());
        user.setPassword(new BCryptPasswordEncoder().encode(saveCommand.getPassword()));
        user.setUserInfo(
                new UserInfo(saveCommand.getRealName(),
                        saveCommand.getEmail(),
                        saveCommand.getPhone(),
                        saveCommand.getSex(),
                        saveCommand.getAge())
        );
        return user;
    }
}
