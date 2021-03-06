package io.futakotome.authService.oauth2.jose.jws;

import io.futakotome.authService.crypto.keys.KeyManager;
import io.futakotome.authService.crypto.keys.ManagedKey;
import io.futakotome.authService.oauth2.jose.JoseHeader;
import io.futakotome.authService.oauth2.jose.JoseHeaderNames;
import io.futakotome.authService.oauth2.jwt.JwtClaimsSet;
import io.futakotome.authService.oauth2.jwt.JwtEncoder;
import io.futakotome.authService.oauth2.jwt.JwtEncodingException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.net.URI;
import java.net.URL;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Nimubus JOSE + JWT SDK实现JWT token的编码并使用JWS进行签名
 *
 * @author futakotome
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token (JWT)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature (JWS)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515#section-3.1">JWS Compact Serialization</a>
 * @see <a target="_blank" href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus JOSE + JWT SDK</a>
 */
public final class NimbusJwsEncoder implements JwtEncoder {
    private static final String ENCODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to encode the Jwt: %s";
    private static final String RSA_KEY_TYPE = "RSA";
    private static final String EC_KEY_TYPE = "EC";
    private static final Map<JwsAlgorithm, String> jcaKeyAlgorithmMappings = new HashMap<JwsAlgorithm, String>() {{
        put(MacAlgorithm.HS256, "HmacSHA256");
        put(MacAlgorithm.HS384, "HmacSHA384");
        put(MacAlgorithm.HS512, "HmacSHA512");
        put(SignatureAlgorithm.RS256, RSA_KEY_TYPE);
        put(SignatureAlgorithm.RS384, RSA_KEY_TYPE);
        put(SignatureAlgorithm.RS512, RSA_KEY_TYPE);
        put(SignatureAlgorithm.ES256, EC_KEY_TYPE);
        put(SignatureAlgorithm.ES384, EC_KEY_TYPE);
        put(SignatureAlgorithm.ES512, EC_KEY_TYPE);
    }};
    private static final Converter<JoseHeader, JWSHeader> jwsHeaderConverter = new JwsHeaderConverter();
    private static final Converter<JwtClaimsSet, JWTClaimsSet> jwtClaimsSetConverter = new JwtClaimsSetConverter();
    private final KeyManager keyManager;

    public NimbusJwsEncoder(KeyManager keyManager) {
        Assert.notNull(keyManager, "keyManager cannot be null");
        this.keyManager = keyManager;
    }

    @Override
    public Jwt encode(JoseHeader headers, JwtClaimsSet claims) throws JwtEncodingException {
        Assert.notNull(headers, "headers cannot be null");
        Assert.notNull(claims, "claims cannot be null");
        ManagedKey managedKey = selectKey(headers);
        if (managedKey == null) {
            throw new JwtEncodingException(String.format(
                    ENCODING_ERROR_MESSAGE_TEMPLATE,
                    "Unsupported key for algorithm '" + headers.getJwsAlgorithm().getName() + "'"));
        }

        JWSSigner jwsSigner;
        if (managedKey.isAsymmetric()) {
            if (!managedKey.getAlgorithm().equals(RSA_KEY_TYPE)) {
                throw new JwtEncodingException(String.format(
                        ENCODING_ERROR_MESSAGE_TEMPLATE,
                        "Unsupported key type '" + managedKey.getAlgorithm() + "'"));
            }
            PrivateKey privateKey = managedKey.getKey();
            jwsSigner = new RSASSASigner(privateKey);
        } else {
            SecretKey secretKey = managedKey.getKey();
            try {
                jwsSigner = new MACSigner(secretKey);
            } catch (KeyLengthException ex) {
                throw new JwtEncodingException(String.format(
                        ENCODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
            }
        }
        headers = JoseHeader.from(headers)
                .type(JOSEObjectType.JWT.getType())
                .keyId(managedKey.getKeyId())
                .build();
        JWSHeader jwsHeader = jwsHeaderConverter.convert(headers);

        claims = JwtClaimsSet.from(claims)
                .id(UUID.randomUUID().toString())
                .build();

        JWTClaimsSet jwtClaimsSet = jwtClaimsSetConverter.convert(claims);

        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);

        try {
            signedJWT.sign(jwsSigner);
        } catch (JOSEException ex) {
            throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
        }
        String jws = signedJWT.serialize();

        return new Jwt(jws, claims.getIssuedAt(), claims.getExpiresAt(),
                headers.getHeaders(), claims.getClaims());
    }

    private ManagedKey selectKey(JoseHeader headers) {
        JwsAlgorithm jwsAlgorithm = headers.getJwsAlgorithm();
        String keyAlgorithm = jcaKeyAlgorithmMappings.get(jwsAlgorithm);
        if (!StringUtils.hasText(keyAlgorithm)) {
            return null;
        }
        Set<ManagedKey> matchingKeys = this.keyManager.findByAlgorithm(keyAlgorithm);
        if (CollectionUtils.isEmpty(matchingKeys)) {
            return null;
        }
        return matchingKeys.stream()
                .filter(ManagedKey::isActive)
                .max(this::mostRecentActivated)
                .orElse(null);
    }

    private int mostRecentActivated(ManagedKey key1, ManagedKey key2) {
        return key1.getActivatedOn().isAfter(key2.getActivatedOn()) ? 1 : -1;
    }

    private static class JwsHeaderConverter implements Converter<JoseHeader, JWSHeader> {

        @Override
        public JWSHeader convert(JoseHeader headers) {
            JWSHeader.Builder builder = new JWSHeader.Builder(JWSAlgorithm.parse(headers.getJwsAlgorithm().getName()));
            Set<String> critical = headers.getCritical();
            if (!CollectionUtils.isEmpty(critical)) {
                builder.criticalParams(critical);
            }

            String contentType = headers.getContentType();
            if (StringUtils.hasText(contentType)) {
                builder.contentType(contentType);
            }

            String jwkSetUri = headers.getJwkSetUri();
            if (StringUtils.hasText(jwkSetUri)) {
                try {
                    builder.jwkURL(new URI(jwkSetUri));
                } catch (Exception ex) {
                    throw new JwtEncodingException(String.format(
                            ENCODING_ERROR_MESSAGE_TEMPLATE,
                            "Failed to convert '" + JoseHeaderNames.JKU + "' JOSE header"), ex);
                }
            }


            Map<String, Object> jwk = headers.getJwk();
            if (!CollectionUtils.isEmpty(jwk)) {
                try {
                    builder.jwk(JWK.parse((JSONObject) jwk));
                } catch (Exception ex) {
                    throw new JwtEncodingException(String.format(
                            ENCODING_ERROR_MESSAGE_TEMPLATE,
                            "Failed to convert '" + JoseHeaderNames.JWK + "' JOSE header"), ex);
                }
            }

            String keyId = headers.getKeyId();
            if (StringUtils.hasText(keyId)) {
                builder.keyID(keyId);
            }

            String type = headers.getType();
            if (StringUtils.hasText(type)) {
                builder.type(new JOSEObjectType(type));
            }


            List<String> x509CertificateChain = headers.getX509CertificateChain();
            if (!CollectionUtils.isEmpty(x509CertificateChain)) {
                builder.x509CertChain(
                        x509CertificateChain.stream()
                                .map(Base64::new)
                                .collect(Collectors.toList()));
            }

            String x509SHA1Thumbprint = headers.getX509SHA1Thumbprint();
            if (StringUtils.hasText(x509SHA1Thumbprint)) {
                builder.x509CertThumbprint(new Base64URL(x509SHA1Thumbprint));
            }

            String x509SHA256Thumbprint = headers.getX509SHA256Thumbprint();
            if (StringUtils.hasText(x509SHA256Thumbprint)) {
                builder.x509CertSHA256Thumbprint(new Base64URL(x509SHA256Thumbprint));
            }

            String x509Uri = headers.getX509Uri();
            if (StringUtils.hasText(x509Uri)) {
                try {
                    builder.x509CertURL(new URI(x509Uri));
                } catch (Exception ex) {
                    throw new JwtEncodingException(String.format(
                            ENCODING_ERROR_MESSAGE_TEMPLATE,
                            "Failed to convert '" + JoseHeaderNames.X5U + "' JOSE header"), ex);
                }
            }

            Map<String, Object> customHeaders = headers.getHeaders().entrySet().stream()
                    .filter(header -> !JWSHeader.getRegisteredParameterNames().contains(header.getKey()))
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            if (!CollectionUtils.isEmpty(customHeaders)) {
                builder.customParams(customHeaders);
            }
            return builder.build();
        }
    }

    private static class JwtClaimsSetConverter implements Converter<JwtClaimsSet, JWTClaimsSet> {

        @Override
        public JWTClaimsSet convert(JwtClaimsSet claims) {
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
            URL issuer = claims.getIssuer();
            if (issuer != null) {
                builder.issuer(issuer.toExternalForm());
            }

            String subject = claims.getSubject();
            if (StringUtils.hasText(subject)) {
                builder.subject(subject);
            }

            List<String> audience = claims.getAudience();
            if (!CollectionUtils.isEmpty(audience)) {
                builder.audience(audience);
            }

            Instant issuedAt = claims.getIssuedAt();
            if (issuedAt != null) {
                builder.issueTime(Date.from(issuedAt));
            }

            Instant expiresAt = claims.getExpiresAt();
            if (expiresAt != null) {
                builder.expirationTime(Date.from(expiresAt));
            }

            Instant notBefore = claims.getNotBefore();
            if (notBefore != null) {
                builder.notBeforeTime(Date.from(notBefore));
            }

            String jwtId = claims.getId();
            if (StringUtils.hasText(jwtId)) {
                builder.jwtID(jwtId);
            }

            Map<String, Object> customClaims = claims.getClaims().entrySet().stream()
                    .filter(claim -> !JWTClaimsSet.getRegisteredNames().contains(claim.getKey()))
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            if (!CollectionUtils.isEmpty(customClaims)) {
                customClaims.forEach(builder::claim);
            }
            return builder.build();
        }
    }
}
