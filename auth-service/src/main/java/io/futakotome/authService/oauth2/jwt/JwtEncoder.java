package io.futakotome.authService.oauth2.jwt;

import io.futakotome.authService.oauth2.jose.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * 结合claims对jwt进行编码
 * <p>
 * JWT有必要加密,因此需要有必要结合JWS签名进行编码或者实现JWE
 *
 * @author futakotome
 * @see Jwt
 * @see JoseHeader
 * @see JwtClaimsSet
 * @see JwtDecoder
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token (JWT)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature (JWS)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7516">JSON Web Encryption (JWE)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515#section-3.1">JWS Compact Serialization</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7516#section-3.1">JWE Compact Serialization</a>
 */
@FunctionalInterface
public interface JwtEncoder {
    /**
     * 结合claims对jwt进行编码
     *
     * @param headers   jose headers
     * @param claimsSet JWT claims set
     * @return a {@link Jwt}
     * @throws JwtEncodingException 编码异常
     */
    Jwt encode(JoseHeader headers, JwtClaimsSet claimsSet) throws JwtEncodingException;
}
