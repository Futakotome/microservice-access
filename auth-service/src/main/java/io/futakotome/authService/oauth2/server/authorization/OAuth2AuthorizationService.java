package io.futakotome.authService.oauth2.server.authorization;

import org.springframework.lang.Nullable;

/**
 * OAuth2 验证crud
 *
 * @author futakotome
 * @see OAuth2Authorization
 */
public interface OAuth2AuthorizationService {
    void save(OAuth2Authorization authorization);

    void remove(OAuth2Authorization authorization);

    OAuth2Authorization findByToken(String token, @Nullable TokenType tokenType);
}
