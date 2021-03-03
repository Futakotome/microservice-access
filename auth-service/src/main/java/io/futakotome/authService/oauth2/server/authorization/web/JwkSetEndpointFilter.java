package io.futakotome.authService.oauth2.server.authorization.web;

import io.futakotome.authService.crypto.keys.KeyManager;
import io.futakotome.authService.crypto.keys.ManagedKey;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.*;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * 拦截JWK Set的请求
 *
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517#section-5">Section 5 JWK Set Format</a>
 */
public class JwkSetEndpointFilter extends OncePerRequestFilter {
    public static final String DEFAULT_JWK_SET_ENDPOINT_URI = "/oauth2/jwks";
    private final KeyManager keyManager;
    private final RequestMatcher requestMatcher;

    public JwkSetEndpointFilter(KeyManager keyManager) {
        this(keyManager, DEFAULT_JWK_SET_ENDPOINT_URI);
    }

    public JwkSetEndpointFilter(KeyManager keyManager, String jwkSetEndpointUri) {
        Assert.notNull(keyManager, "keyManager cannot be null");
        Assert.hasText(jwkSetEndpointUri, "jwkSetEndpointUri cannot be empty");
        this.keyManager = keyManager;
        this.requestMatcher = new AntPathRequestMatcher(jwkSetEndpointUri, HttpMethod.GET.name());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!this.requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        JWKSet jwkSet = buildJwkSet();
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        try (Writer writer = response.getWriter()) {
            writer.write(jwkSet.toString());
        }
    }

    private JWKSet buildJwkSet() {
        return new JWKSet(
                this.keyManager.getKeys().stream()
                        .filter(managedKey -> managedKey.isActive() && managedKey.isAsymmetric())
                        .map(this::convert)
                        .filter(Objects::nonNull)
                        .collect(Collectors.toList())
        );
    }

    private JWK convert(ManagedKey managedKey) {
        JWK jwk = null;
        if (managedKey.getPublicKey() instanceof RSAPublicKey) {
            RSAPublicKey publicKey = (RSAPublicKey) managedKey.getPublicKey();
            jwk = new RSAKey.Builder(publicKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyID(managedKey.getKeyId())
                    .build();
        } else if (managedKey.getPublicKey() instanceof ECPublicKey) {
            ECPublicKey publicKey = (ECPublicKey) managedKey.getPublicKey();
            Curve curve = Curve.forECParameterSpec(publicKey.getParams());
            jwk = new ECKey.Builder(curve, publicKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.ES256)
                    .keyID(managedKey.getKeyId())
                    .build();
        }
        return jwk;
    }
}
