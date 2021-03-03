package io.futakotome.authService.oauth2.server.authorization.client;

/**
 * 获取客户端的repo,理解为dao即可
 *
 * @author futakotome
 */
public interface RegisteredClientRepository {
    RegisteredClient findById(String id);

    RegisteredClient findByClientId(String clientId);
}
