package io.futakotome.authService.oauth2.server.authorization.web;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * 委托类处理不同GRANT_TYPE的请求
 *
 * @see OAuth2ParameterNames#GRANT_TYPE
 */

public class DelegatingAuthorizationGrantAuthenticationConverter implements Converter<HttpServletRequest, Authentication> {

    private final Map<AuthorizationGrantType, Converter<HttpServletRequest, Authentication>> converters;

    public DelegatingAuthorizationGrantAuthenticationConverter(Map<AuthorizationGrantType, Converter<HttpServletRequest, Authentication>> converters) {
        Assert.notEmpty(converters, "converters cannot be empty");
        this.converters = Collections.unmodifiableMap(new HashMap<>(converters));
    }

    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        Assert.notNull(request, "request cannot be null");

        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (StringUtils.isEmpty(grantType)) {
            return null;
        }
        Converter<HttpServletRequest, Authentication> converter =
                this.converters.get(new AuthorizationGrantType(grantType));
        if (converter == null) {
            return null;
        }
        return converter.convert(request);
    }
}
