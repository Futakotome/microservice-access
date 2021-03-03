package io.futakotome.authService.oauth2.server.authorization.web;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

final class OAuth2EndpointUtils {
    private OAuth2EndpointUtils() {
    }

    static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            if (values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });
        return parameters;
    }

    static boolean matchesPkceTokenRequest(HttpServletRequest request) {
        return AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(
                request.getParameter(OAuth2ParameterNames.GRANT_TYPE)) &&
                request.getParameter(OAuth2ParameterNames.CODE) != null &&
                request.getParameter(PkceParameterNames.CODE_VERIFIER) != null;
    }
}
