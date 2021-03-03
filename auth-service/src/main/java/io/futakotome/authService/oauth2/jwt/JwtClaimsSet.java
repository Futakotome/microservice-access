package io.futakotome.authService.oauth2.jwt;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimAccessor;
import org.springframework.util.Assert;

import java.net.URL;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.security.oauth2.jwt.JwtClaimNames.*;

/**
 * 传达JWT声明信息
 *
 * @author futakotome
 * @see Jwt
 * @see JwtClaimAccessor
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519#section-4">JWT Claims Set</a>
 */
public class JwtClaimsSet implements JwtClaimAccessor {

    private final Map<String, Object> claims;

    private JwtClaimsSet(Map<String, Object> claims) {
        this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    }

    public static Builder withClaims() {
        return new Builder();
    }

    public static Builder from(JwtClaimsSet claims) {
        return new Builder(claims);
    }

    @Override
    public Map<String, Object> getClaims() {
        return this.claims;
    }

    public static class Builder {

        private final Map<String, Object> claims = new LinkedHashMap<>();

        public Builder(JwtClaimsSet claims) {
            Assert.notNull(claims, "Claims must not be null.");
            this.claims.putAll(claims.getClaims());
        }

        public Builder() {
        }

        public Builder issuer(URL issuer) {
            return claim(ISS, issuer);
        }

        public Builder subject(String subject) {
            return claim(SUB, subject);
        }

        public Builder audience(List<String> audience) {
            return claim(AUD, audience);
        }

        public Builder expiresAt(Instant expiresAt) {
            return claim(EXP, expiresAt);
        }

        public Builder notBefore(Instant notBefore) {
            return claim(NBF, notBefore);
        }

        public Builder issuedAt(Instant issuedAt) {
            return claim(IAT, issuedAt);
        }

        public Builder id(String jti) {
            return claim(JTI, jti);
        }

        public Builder claim(String name, Object value) {
            Assert.hasText(name, "Claims name cannot be empty");
            Assert.notNull(value, "Claims value cannot be null");
            this.claims.put(name, value);
            return this;
        }

        public JwtClaimsSet build() {
            Assert.notEmpty(this.claims, "claims cannot be empty");
            return new JwtClaimsSet(this.claims);
        }
    }
}
