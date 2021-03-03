package io.futakotome.tenantService.domain.user.infrastructure.data;

import io.futakotome.tenantService.domain.user.core.model.Sex;

import javax.persistence.AttributeConverter;

public class SexConverter implements AttributeConverter<Sex, Integer> {
    @Override
    public Integer convertToDatabaseColumn(Sex sex) {
        return sex.getValue();
    }

    @Override
    public Sex convertToEntityAttribute(Integer integer) {
        return Sex.valueOf(integer);
    }
}
