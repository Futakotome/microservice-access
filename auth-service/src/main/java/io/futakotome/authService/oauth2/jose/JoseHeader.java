package io.futakotome.authService.oauth2.jose;

import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.util.Assert;

import java.util.*;
import java.util.function.Consumer;

/**
 * JOSE Header 是JWT的组成部分,无论它是JWS还是JWE
 *
 * @author futakotome
 * @see org.springframework.security.oauth2.jwt.Jwt
 */
public final class JoseHeader {
    private final Map<String, Object> headers;

    private JoseHeader(Map<String, Object> headers) {
        this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
    }

    public JwsAlgorithm getJwsAlgorithm() {
        return getHeader(JoseHeaderNames.ALG);
    }

    public String getJwkSetUri() {
        return getHeader(JoseHeaderNames.JKU);
    }

    public Map<String, Object> getJwk() {
        return getHeader(JoseHeaderNames.JWK);
    }

    public String getKeyId() {
        return getHeader(JoseHeaderNames.KID);
    }

    public String getX509Uri() {
        return getHeader(JoseHeaderNames.X5U);
    }

    public List<String> getX509CertificateChain() {
        return getHeader(JoseHeaderNames.X5C);
    }

    public String getX509SHA1Thumbprint() {
        return getHeader(JoseHeaderNames.X5T);
    }

    public String getX509SHA256Thumbprint() {
        return getHeader(JoseHeaderNames.X5T_S256);
    }

    public String getContentType() {
        return getHeader(JoseHeaderNames.CTY);
    }

    public Set<String> getCritical() {
        return getHeader(JoseHeaderNames.CRIT);
    }

    public String getType() {
        return getHeader(JoseHeaderNames.TYP);
    }


    public Map<String, Object> getHeaders() {
        return this.headers;
    }

    /**
     * 根据JOSE头返回构造器
     *
     * @param headers
     * @return {@link Builder}
     */
    public static Builder from(JoseHeader headers) {
        return new Builder(headers);
    }

    /**
     * 根据jws加密算法返回构造器
     *
     * @param jwsAlgorithm
     * @return {@link Builder}
     */
    public static Builder withAlgorithm(JwsAlgorithm jwsAlgorithm) {
        return new Builder(jwsAlgorithm);
    }

    @SuppressWarnings("unchecked")
    public <T> T getHeader(String name) {
        Assert.hasText(name, "header name must not be empty!");
        return (T) getHeaders().get(name);
    }

    public static class Builder {
        private final Map<String, Object> headers = new LinkedHashMap<>();

        private Builder(JwsAlgorithm jwsAlgorithm) {
            Assert.notNull(jwsAlgorithm, "jws algorithm must not be null.");
            header(JoseHeaderNames.ALG, jwsAlgorithm);
        }

        private Builder(JoseHeader joseHeader) {
            Assert.notNull(joseHeader, "header must not be null.");
            this.headers.putAll(joseHeader.headers);
        }

        public Builder jwkSetUri(String jwkSetUri) {
            return header(JoseHeaderNames.JKU, jwkSetUri);
        }

        public Builder jwk(Map<String, Object> jwk) {
            return header(JoseHeaderNames.JWK, jwk);
        }

        public Builder keyId(String keyId) {
            return header(JoseHeaderNames.KID, keyId);
        }

        public Builder x509Uri(String x509Uri) {
            return header(JoseHeaderNames.X5U, x509Uri);
        }

        public Builder x509CertificateChain(List<String> x509CertificateChain) {
            return header(JoseHeaderNames.X5C, x509CertificateChain);
        }

        public Builder x509SHA1Thumbprint(String x509SHA1Thumbprint) {
            return header(JoseHeaderNames.X5T, x509SHA1Thumbprint);
        }

        public Builder x509SHA256Thumbprint(String x509SHA256Thumbprint) {
            return header(JoseHeaderNames.X5T_S256, x509SHA256Thumbprint);
        }

        public Builder critical(Set<String> headerNames) {
            return header(JoseHeaderNames.CRIT, headerNames);
        }

        public Builder type(String type) {
            return header(JoseHeaderNames.TYP, type);
        }

        public Builder contentType(String contentType) {
            return header(JoseHeaderNames.CTY, contentType);
        }

        public Builder headers(Consumer<Map<String, Object>> headersConsumer) {
            headersConsumer.accept(this.headers);
            return this;
        }

        public JoseHeader build() {
            Assert.notEmpty(this.headers, "headers cannot be empty");
            return new JoseHeader(this.headers);
        }

        public Builder header(String name, Object value) {
            Assert.hasText(name, "header name cannot be empty");
            Assert.notNull(value, "header value cannot be null");
            this.headers.put(name, value);
            return this;
        }
    }
}
