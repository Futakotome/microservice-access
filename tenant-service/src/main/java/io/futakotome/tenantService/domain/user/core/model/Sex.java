package io.futakotome.tenantService.domain.user.core.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Objects;

@Getter
@AllArgsConstructor
public enum Sex {
    MALE(1),
    FEMALE(0);

    private final int value;

    public static Sex valueOf(Integer value) {
        for (Sex sex : Sex.values()) {
            if (Objects.equals(value, sex.getValue())) {
                return sex;
            }
        }
        throw new IllegalArgumentException("Cannot found the sex by value : " + value);
    }
}
