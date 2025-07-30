package mujina.idp;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * SP注册表 - 管理多个Service Provider的配置信息
 * 支持通过配置文件或API动态管理SP列表
 */
@Component
@ConfigurationProperties(prefix = "idp.sp-registry")
public class SpRegistry {

    private List<ServiceProvider> providers = new ArrayList<>();

    public List<ServiceProvider> getProviders() {
        return providers;
    }

    public void setProviders(List<ServiceProvider> providers) {
        this.providers = providers;
    }

    /**
     * 根据SP ID查找Service Provider
     */
    public ServiceProvider findById(String spId) {
        return providers.stream()
                .filter(sp -> sp.getId().equals(spId))
                .findFirst()
                .orElse(null);
    }

    /**
     * 添加新的Service Provider
     */
    public void addProvider(ServiceProvider provider) {
        providers.add(provider);
    }

    /**
     * 移除Service Provider
     */
    public boolean removeProvider(String spId) {
        return providers.removeIf(sp -> sp.getId().equals(spId));
    }

    /**
     * Service Provider配置类
     */
    public static class ServiceProvider {
        private String id;
        private String name;
        private String description;
        private String entityId;
        private String acsUrl;
        private String logoUrl;
        private boolean enabled = true;

        // 构造函数
        public ServiceProvider() {}

        public ServiceProvider(String id, String name, String entityId, String acsUrl) {
            this.id = id;
            this.name = name;
            this.entityId = entityId;
            this.acsUrl = acsUrl;
        }

        // Getters and Setters
        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getEntityId() {
            return entityId;
        }

        public void setEntityId(String entityId) {
            this.entityId = entityId;
        }

        public String getAcsUrl() {
            return acsUrl;
        }

        public void setAcsUrl(String acsUrl) {
            this.acsUrl = acsUrl;
        }

        public String getLogoUrl() {
            return logoUrl;
        }

        public void setLogoUrl(String logoUrl) {
            this.logoUrl = logoUrl;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }
}