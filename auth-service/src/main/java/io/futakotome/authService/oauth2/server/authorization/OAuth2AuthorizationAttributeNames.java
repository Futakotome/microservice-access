package io.futakotome.authService.oauth2.server.authorization;

/**
 * 验证里bean里的属性
 * {@link OAuth2Authorization#getAttributes()}{@code Map}
 *
 * @author
 * @see OAuth2Authorization#getAttributes()
 */
public interface OAuth2AuthorizationAttributeNames {
    String STATE = OAuth2Authorization.class.getName().concat(".STATE");

    /**
     * {@link org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames#CODE} 参数
     */
    String CODE = OAuth2Authorization.class.getName().concat(".CODE");

    /**
     * {@link org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest}
     */
    String AUTHORIZATION_REQUEST = OAuth2Authorization.class.getName().concat(".AUTHORIZATION_REQUEST");

    /**
     * 验证范围
     */
    String AUTHORIZED_SCOPES = OAuth2Authorization.class.getName().concat(".AUTHORIZED_SCOPES");
    /**
     * {@link org.springframework.security.oauth2.core.OAuth2AccessToken} 的属性
     */
    String ACCESS_TOKEN_ATTRIBUTES = OAuth2Authorization.class.getName().concat(".ACCESS_TOKEN_ATTRIBUTES");
}
