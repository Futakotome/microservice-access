package io.futakotome.tenantService.infrastructure.config.domain;

import io.futakotome.tenantService.domain.user.core.ports.UserFacade;
import io.futakotome.tenantService.domain.user.core.ports.incoming.UserFetch;
import io.futakotome.tenantService.domain.user.core.ports.incoming.UserStore;
import io.futakotome.tenantService.domain.user.core.ports.outgoing.UserRepository;
import io.futakotome.tenantService.domain.user.infrastructure.UserSpringDataJpaAdapter;
import io.futakotome.tenantService.domain.user.infrastructure.data.UserSpringDataJpaRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class UserDomainConfig {

    @Bean
    public UserRepository userRepository(UserSpringDataJpaRepository userSpringDataJpaRepository) {
        return new UserSpringDataJpaAdapter(userSpringDataJpaRepository);
    }

    @Bean
    public UserStore userStore(UserRepository userRepository) {
        return new UserFacade(userRepository);
    }

    @Bean
    public UserFetch userFetch(UserRepository userRepository) {
        return new UserFacade(userRepository);
    }
}
