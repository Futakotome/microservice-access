package io.futakotome.authService.oauth2.server.authorization.web;

import io.futakotome.authService.oauth2.server.authorization.authorization.OAuth2ClientAuthenticationToken;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * 处理request中的basic 验证
 */
public class ClientSecretBasicAuthenticationConverter implements AuthenticationConverter {
    @Override
    public Authentication convert(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null) {
            return null;
        }

        String[] parts = header.split("\\s");
        if (!parts[0].equalsIgnoreCase("Basic")) {
            return null;
        }

        if (parts.length != 2) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
        }

        byte[] decodedCredentials;
        try {
            decodedCredentials = Base64.getDecoder().decode(
                    parts[1].getBytes(StandardCharsets.UTF_8));
        } catch (IllegalArgumentException ex) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), ex);
        }

        String credentialsString = new String(decodedCredentials, StandardCharsets.UTF_8);
        String[] credentials = credentialsString.split(":", 2);
        if (credentials.length != 2 ||
                !StringUtils.hasText(credentials[0]) ||
                !StringUtils.hasText(credentials[1])) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
        }

        String clientID;
        String clientSecret;
        try {
            clientID = URLDecoder.decode(credentials[0], StandardCharsets.UTF_8.name());
            clientSecret = URLDecoder.decode(credentials[1], StandardCharsets.UTF_8.name());
        } catch (Exception ex) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), ex);
        }

        return new OAuth2ClientAuthenticationToken(clientID, clientSecret, extractAdditionalParameters(request));
    }

    private static Map<String, Object> extractAdditionalParameters(HttpServletRequest request) {
        Map<String, Object> additionalParameters = Collections.emptyMap();
        if (OAuth2EndpointUtils.matchesPkceTokenRequest(request)) {
            additionalParameters = new HashMap<>(OAuth2EndpointUtils.getParameters(request).toSingleValueMap());
        }
        return additionalParameters;
    }
}
