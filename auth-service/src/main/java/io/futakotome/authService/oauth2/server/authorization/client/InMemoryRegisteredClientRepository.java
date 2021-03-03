package io.futakotome.authService.oauth2.server.authorization.client;

import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * token存储在内存中,适合测试
 *
 * @author futakotome
 * @see RegisteredClientRepository
 */
public class InMemoryRegisteredClientRepository implements RegisteredClientRepository {

    private final Map<String, RegisteredClient> idRegistrationMap;

    private final Map<String, RegisteredClient> clientIdRegistrationMap;

    public InMemoryRegisteredClientRepository(RegisteredClient... registrations) {
        this(Arrays.asList(registrations));
    }

    public InMemoryRegisteredClientRepository(List<RegisteredClient> registrations) {
        Assert.notEmpty(registrations, "registrations cannot be empty");
        ConcurrentHashMap<String, RegisteredClient> idRegistrationMapResult = new ConcurrentHashMap<>();
        ConcurrentHashMap<String, RegisteredClient> clientIdRegistrationMapResult = new ConcurrentHashMap<>();
        for (RegisteredClient registration : registrations) {
            Assert.notNull(registration, "registration cannot be null");
            String id = registration.getId();
            if (idRegistrationMapResult.containsKey(id)) {
                throw new IllegalArgumentException("Registered client must be unique. " +
                        "Found duplicate identifier: " + id);
            }
            String clientId = registration.getClientId();
            if (clientIdRegistrationMapResult.containsKey(clientId)) {
                throw new IllegalArgumentException("Registered client must be unique. " +
                        "Found duplicate client identifier: " + clientId);
            }
            idRegistrationMapResult.put(id, registration);
            clientIdRegistrationMapResult.put(clientId, registration);
        }
        this.idRegistrationMap = idRegistrationMapResult;
        this.clientIdRegistrationMap = clientIdRegistrationMapResult;
    }

    @Override
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return this.idRegistrationMap.get(id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        return this.clientIdRegistrationMap.get(clientId);
    }
}
