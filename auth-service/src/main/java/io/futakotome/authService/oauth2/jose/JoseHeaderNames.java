package io.futakotome.authService.oauth2.jose;

/**
 * JSON Web Token(jwt)、JSON Web Signature(jws)、JSON Web Encryption(jwe)头部字段
 *
 * @author futakotome
 * @see JoseHeader
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519#section-5">JWT JOSE Header</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515#section-4">JWS JOSE Header</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7516#section-4">JWE JOSE Header</a>
 */
public interface JoseHeaderNames {
    /**
     * {@code alg} jws或jwe加密算法
     */
    String ALG = "alg";
    /**
     * {@code jku} JWK Set Url ,公钥在哪里?
     */
    String JKU = "jku";

    /**
     * {@code jkw} JSON Web Key ,签名jws或加密jwe的公钥
     */
    String JWK = "jwk";
    /**
     * {@code kid} 指出哪个key被用于签名或加密
     */
    String KID = "kid";
    //===========================X.509相关===========
    String X5U = "x5u";

    String X5C = "x5c";

    String X5T = "x5t";

    String X5T_S256 = "x5t#S256";
    //===============================================
    /**
     * {@code typ} 修饰jws/jwe application的media type
     */
    String TYP = "typ";
    /**
     * {@code cty} 修饰jws/jwe application的payload的media type
     */
    String CTY = "cty";

    /**
     * {@code crit}扩展相关
     */
    String CRIT = "crit";
}
