package io.futakotome.authService.oauth2.server.authorization.web;

import io.futakotome.authService.oauth2.server.authorization.authorization.OAuth2ClientAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;

/**
 * 解析request提取参数校验
 *
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7636">Proof Key for Code Exchange by OAuth Public Clients</a>
 */
public class PublicClientAuthenticationConverter implements AuthenticationConverter {
    @Override
    public Authentication convert(HttpServletRequest httpServletRequest) {
        if (!OAuth2EndpointUtils.matchesPkceTokenRequest(httpServletRequest)) {
            return null;
        }
        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(httpServletRequest);
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId)) {
            return null;
        }
        if (parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
        }

        if (parameters.get(PkceParameterNames.CODE_VERIFIER).size() != 1) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
        }

        parameters.remove(OAuth2ParameterNames.CLIENT_ID);

        return new OAuth2ClientAuthenticationToken(clientId, new HashMap<>(parameters.toSingleValueMap()));

    }
}
