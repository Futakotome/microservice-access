package io.futakotome.tenantService.domain;

import org.hibernate.annotations.GenericGenerator;
import org.springframework.data.domain.AbstractAggregateRoot;

import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.MappedSuperclass;

@MappedSuperclass
public abstract class DomainBase<T extends DomainBase<T>> extends AbstractAggregateRoot<T> {
    @Id
    @GenericGenerator(name = "idGenerator", strategy = "uuid2")
    @GeneratedValue(generator = "idGenerator")
    private String id;

    public String getId() {
        return id;
    }

    public boolean sameIdentityAs(final T that) {
        return this.equals(that);
    }

    @Override
    public boolean equals(final Object object) {
        if (!(object instanceof DomainBase)) {
            return false;
        }
        final DomainBase<?> that = (DomainBase<?>) object;
        _checkIdentity(this);
        _checkIdentity(that);
        return this.id.equals(that.getId());
    }

    private void _checkIdentity(final DomainBase<?> domainBase) {
        if (domainBase.getId() == null) {
            throw new IllegalArgumentException("Identity missing in the domain: " + domainBase);
        }
    }

    @Override
    public int hashCode() {
        return getId() != null ? getId().hashCode() : 0;
    }
}
