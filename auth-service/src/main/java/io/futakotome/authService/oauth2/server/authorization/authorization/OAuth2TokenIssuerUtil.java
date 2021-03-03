package io.futakotome.authService.oauth2.server.authorization.authorization;

import io.futakotome.authService.oauth2.jose.JoseHeader;
import io.futakotome.authService.oauth2.jwt.JwtClaimsSet;
import io.futakotome.authService.oauth2.jwt.JwtEncoder;
import io.futakotome.authService.oauth2.server.authorization.token.OAuth2RefreshToken;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;

class OAuth2TokenIssuerUtil {
    private static final StringKeyGenerator TOKEN_GENERATOR = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    static Jwt issueJwtAccessToken(JwtEncoder jwtEncoder, String subject, String audience, Set<String> scopes) {
        JoseHeader joseHeader = JoseHeader.withAlgorithm(SignatureAlgorithm.RS256).build();
        // TODO 应该允许配置provider地址
        URL issuer = null;
        try {
            issuer = URI.create("https://oauth2.provider.com").toURL();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);

        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.withClaims()
                .issuer(issuer)
                .subject(subject)
                .audience(Collections.singletonList(audience))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .notBefore(issuedAt)
                .claim(OAuth2ParameterNames.SCOPE, scopes)
                .build();

        return jwtEncoder.encode(joseHeader, jwtClaimsSet);
    }

    static OAuth2RefreshToken issueRefreshToken(Duration refreshTokenTimeToLive) {
        Instant issuedAt = Instant.now();
        //todo 可以把refreshToken也编码成jwt
        Instant expiresAt = issuedAt.plus(refreshTokenTimeToLive);

        return new OAuth2RefreshToken(TOKEN_GENERATOR.generateKey(), issuedAt, expiresAt);
    }

    //todo id_token目前只有唯一标识sub
    static Jwt issueIdToken(JwtEncoder jwtEncoder, String subject) {
        JoseHeader joseHeader = JoseHeader.withAlgorithm(SignatureAlgorithm.RS256).build();
        URL issuer = null;
        try {
            issuer = URI.create("https://oauth2.provider.com").toURL();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);

        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.withClaims()
                .issuer(issuer)
                .subject(subject)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .notBefore(issuedAt)
                .build();

        return jwtEncoder.encode(joseHeader, jwtClaimsSet);
    }
}
