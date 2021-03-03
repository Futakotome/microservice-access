package io.futakotome.authService.oauth2.server.authorization.config;

import io.futakotome.authService.oauth2.server.authorization.Version;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * 设置
 *
 * @author futakotome
 */
public class Settings implements Serializable {
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
    private final Map<String, Object> settings;

    public Settings() {
        this.settings = new HashMap<>();
    }

    public Settings(Map<String, Object> settings) {
        Assert.notNull(settings, "settings cannot be null");
        this.settings = new HashMap<>(settings);
    }

    @SuppressWarnings("unchecked")
    public <T> T setting(String name) {
        Assert.hasText(name, "name cannot be empty");
        return (T) this.settings.get(name);
    }

    @SuppressWarnings("unchecked")
    public <T extends Settings> T setting(String name, Object value) {
        Assert.hasText(name, "name cannot be empty");
        Assert.notNull(value, "value cannot be null");
        this.settings.put(name, value);
        return (T) this;
    }

    public Map<String, Object> settings() {
        return this.settings;
    }

    @SuppressWarnings("unchecked")
    public <T extends Settings> T settings(Consumer<Map<String, Object>> settingsConsumer) {
        settingsConsumer.accept(this.settings);
        return (T) this;
    }
}
