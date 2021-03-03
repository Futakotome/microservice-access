package io.futakotome.gatewayService.filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Component
public class AuthorizeGatewayFilterFactory extends
        AbstractGatewayFilterFactory<AuthorizeGatewayFilterFactory.Config> {

    private static final Log log = LogFactory.getLog(AuthorizeGatewayFilterFactory.class);

    private static final String ISSUER_URI = "https://oauth2.provider.com";

    private static final String JWKS_URI = "http://localhost:9000/auth/oauth2/jwks";

    private static final String AUTHORIZATION_HEADER = "Authorization";

    private static final String BEARER = "Bearer";

    public AuthorizeGatewayFilterFactory() {
        super(Config.class);
        log.info("自定义网关过滤器[" + AuthorizeGatewayFilterFactory.class.getName() + "]装载!");
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList("enabled");
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            if (config.isEnabled()) {
                ServerHttpRequest request = exchange.getRequest();
                ServerHttpResponse response = exchange.getResponse();
                String authenticationHeader = request.getHeaders().getFirst(AUTHORIZATION_HEADER);
                if (authenticationHeader == null) {
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    return response.setComplete();
                }
                String bearerToken = bearTokenExtractor(authenticationHeader);
                if (bearerToken == null) {
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    return response.setComplete();
                }
                try {
                    jwtDecodeHandler(bearerToken);
                } catch (JwtException jwtException) {
                    response.setStatusCode(HttpStatus.FORBIDDEN);
                    log.error(jwtException.getMessage());
                    return response.setComplete();
                }
            }
            return chain.filter(exchange);
        };
    }

    private void jwtDecodeHandler(String bearerToken) throws JwtException {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(JWKS_URI)
                .jwsAlgorithm(SignatureAlgorithm.from("RS256")).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(ISSUER_URI));
        Jwt decodedJwt = decoder.decode(bearerToken);
        String user = decodedJwt.getClaim("sub");
        String client = decodedJwt.getClaim("aud").toString();
        log.info("使用客户端:[" + client + "]的用户:[" + user + "]=========>");
    }

    private static String bearTokenExtractor(String token) {
        String[] entireToken = token.split("\\s");
        String tokenPrefix = entireToken[0];
        if (!bearerValidate(tokenPrefix)) {
            return null;
        }
        return entireToken[1];
    }

    private static boolean bearerValidate(String tokenPrefix) {
        return BEARER.equals(tokenPrefix);
    }

    public static class Config {
        private boolean enabled;

        public Config() {
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }
}
