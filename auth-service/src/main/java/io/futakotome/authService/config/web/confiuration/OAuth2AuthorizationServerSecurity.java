package io.futakotome.authService.config.web.confiuration;

import io.futakotome.authService.config.web.configurer.OAuth2AuthorizationServerConfigurer;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Order(Ordered.HIGHEST_PRECEDENCE)
public class OAuth2AuthorizationServerSecurity extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        applyDefaultConfiguration(http);
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/webjars/**"); //todo webjar拦截未处理
    }

    private static void applyDefaultConfiguration(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<>();
        RequestMatcher[] endpointMatchers = authorizationServerConfigurer
                .getEndpointMatchers()
                .toArray(new RequestMatcher[0]);
        http.requestMatcher(new OrRequestMatcher(endpointMatchers))
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin(form -> form.loginPage("/login.html").permitAll())
                .csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.ignoringRequestMatchers(endpointMatchers))
                .apply(authorizationServerConfigurer);

    }
}
