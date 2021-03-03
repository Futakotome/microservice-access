package io.futakotome.tenantService.domain.saas.core.model;

import io.futakotome.tenantService.domain.DomainBase;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.Column;
import javax.persistence.Entity;

@Getter
@Setter
@Entity(name = "t_saas")
public class Saas extends DomainBase<Saas> {

    @Column(name = "saas_name")
    private String name;

}
