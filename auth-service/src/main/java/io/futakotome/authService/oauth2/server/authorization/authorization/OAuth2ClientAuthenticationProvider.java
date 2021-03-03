package io.futakotome.authService.oauth2.server.authorization.authorization;

import io.futakotome.authService.oauth2.server.authorization.OAuth2Authorization;
import io.futakotome.authService.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import io.futakotome.authService.oauth2.server.authorization.OAuth2AuthorizationService;
import io.futakotome.authService.oauth2.server.authorization.TokenType;
import io.futakotome.authService.oauth2.server.authorization.client.RegisteredClient;
import io.futakotome.authService.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;

public class OAuth2ClientAuthenticationProvider implements AuthenticationProvider {
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;

    public OAuth2ClientAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
                                              OAuth2AuthorizationService authorizationService) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;
        String clientId = clientAuthentication.getPrincipal().toString();
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throwInvalidClient();
        }
        if (clientAuthentication.getCredentials() != null) {
            String clientSecret = clientAuthentication.getCredentials().toString();
            // TODO Use PasswordEncoder.matches()
            if (!registeredClient.getClientSecret().equals(clientSecret)) {
                throwInvalidClient();
            }
        }
        authenticatePkceIfAvailable(clientAuthentication, registeredClient);

        return new OAuth2ClientAuthenticationToken(registeredClient);
    }

    private void authenticatePkceIfAvailable(OAuth2ClientAuthenticationToken clientAuthentication, RegisteredClient registeredClient) {
        Map<String, Object> parameters = clientAuthentication.getAdditionalParameters();
        if (CollectionUtils.isEmpty(parameters) || !authorizationCodeGrant(parameters)) {
            return;
        }
        OAuth2Authorization authorization = this.authorizationService.findByToken(
                (String) parameters.get(OAuth2ParameterNames.CODE),
                TokenType.AUTHORIZATION_CODE);
        if (authorization == null) {
            throwInvalidClient();
        }
        OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST);
        String codeChallenge = (String) authorizationRequest.getAdditionalParameters()
                .get(PkceParameterNames.CODE_CHALLENGE);
        if (StringUtils.hasText(codeChallenge)) {
            String codeChallengeMethod = (String) authorizationRequest.getAdditionalParameters()
                    .get(PkceParameterNames.CODE_CHALLENGE_METHOD);
            String codeVerifier = (String) parameters.get(PkceParameterNames.CODE_VERIFIER);
            if (!codeVerifierValid(codeVerifier, codeChallenge, codeChallengeMethod)) {
                throwInvalidClient();
            }
        } else if (registeredClient.getClientSettings().requireProofKey()) {
            throwInvalidClient();
        }
    }

    private static boolean codeVerifierValid(String codeVerifier, String codeChallenge, String codeChallengeMethod) {
        if (!StringUtils.hasText(codeVerifier)) {
            return false;
        } else if (!StringUtils.hasText(codeChallengeMethod) || "plain".equals(codeChallengeMethod)) {
            return codeVerifier.equals(codeChallenge);
        } else if ("S256".equals(codeChallengeMethod)) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
                String encodedVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
                return encodedVerifier.equals(codeChallenge);
            } catch (NoSuchAlgorithmException ex) {
                ex.printStackTrace();
            }
        }
        throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR));
    }

    private static void throwInvalidClient() {
        throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
    }

    private static boolean authorizationCodeGrant(Map<String, Object> parameters) {
        return AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(
                parameters.get(OAuth2ParameterNames.GRANT_TYPE)) &&
                parameters.get(OAuth2ParameterNames.CODE) != null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
