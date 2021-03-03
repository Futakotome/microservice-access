package io.futakotome.authService.oauth2.server.authorization.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

/**
 * 处理验证OAuth2请求
 *
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-2.3">Section 2.3 Client Authentication</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-3.2.1">Section 3.2.1 Token Endpoint Client Authentication</a>
 */
public class OAuth2ClientAuthenticationFilter extends OncePerRequestFilter {
    private final AuthenticationManager authenticationManager;
    private final RequestMatcher requestMatcher;
    private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();
    private AuthenticationConverter authenticationConverter;
    private AuthenticationSuccessHandler authenticationSuccessHandler;
    private AuthenticationFailureHandler authenticationFailureHandler;

    public OAuth2ClientAuthenticationFilter(AuthenticationManager authenticationManager, RequestMatcher requestMatcher) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(requestMatcher, "requestMatcher cannot be null");
        this.authenticationManager = authenticationManager;
        this.requestMatcher = requestMatcher;
        this.authenticationConverter = new DelegatingAuthenticationConverter(Arrays.asList(
                new ClientSecretBasicAuthenticationConverter(),
                new PublicClientAuthenticationConverter()));
        this.authenticationSuccessHandler = this::onAuthenticationSuccess;
        this.authenticationFailureHandler = this::onAuthenticationFailure;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (this.requestMatcher.matches(request)) {
            try {
                Authentication authenticationRequest = this.authenticationConverter.convert(request);
                if (authenticationRequest != null) {
                    Authentication authenticationResult = this.authenticationManager.authenticate(authenticationRequest);
                    this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authenticationResult);
                }
            } catch (OAuth2AuthenticationException failed) {
                this.authenticationFailureHandler.onAuthenticationFailure(request, response, failed);
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    public final void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
        Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
        this.authenticationConverter = authenticationConverter;
    }

    public final void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
        Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
        this.authenticationSuccessHandler = authenticationSuccessHandler;
    }

    public final void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
        Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
        this.authenticationFailureHandler = authenticationFailureHandler;
    }

    private void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                         Authentication authentication) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
    }

    private void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationException failed) throws IOException {
        SecurityContextHolder.clearContext();

        OAuth2Error error = ((OAuth2AuthenticationException) failed).getError();
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        if (OAuth2ErrorCodes.INVALID_CLIENT.equals(error.getErrorCode())) {
            httpResponse.setStatusCode(HttpStatus.UNAUTHORIZED);
        } else {
            httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
        }
        this.errorHttpResponseConverter.write(error, null, httpResponse);
    }

}
