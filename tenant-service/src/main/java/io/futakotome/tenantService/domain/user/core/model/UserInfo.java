package io.futakotome.tenantService.domain.user.core.model;

import io.futakotome.tenantService.domain.user.infrastructure.data.SexConverter;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.Convert;
import javax.persistence.Embeddable;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Embeddable
public class UserInfo {

    private String realName;

    private String email;

    private String phone;

    @Convert(converter = SexConverter.class)
    private Sex sex;

    private Integer age;


}
