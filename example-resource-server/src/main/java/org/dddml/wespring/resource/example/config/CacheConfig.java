package org.dddml.wespring.resource.example.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

/**
 * 缓存配置
 * 
 * 配置Caffeine缓存来提高组权限查询的性能。
 * 
 * 缓存策略：
 * - 过期时间：1小时（可根据需要调整）
 * - 最大缓存条目：100个
 * - 启用统计信息收集
 * 
 * 注意：当WeSpringAuthServer中的组权限配置发生变化时，
 * 可能需要手动清除缓存或等待缓存过期。
 */
@Configuration
@EnableCaching
public class CacheConfig {
    
    private static final Logger logger = LoggerFactory.getLogger(CacheConfig.class);

    /**
     * Caffeine缓存配置
     */
    @Bean
    public Caffeine<Object, Object> caffeineConfig() {
        return Caffeine.newBuilder()
                // 写入后1小时过期
                .expireAfterWrite(1, TimeUnit.HOURS)
                // 最大缓存100个条目
                .maximumSize(100)
                // 启用统计信息收集（用于监控缓存性能）
                .recordStats();
    }

    /**
     * 缓存管理器
     */
    @Bean
    public CacheManager cacheManager(Caffeine<Object, Object> caffeine) {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager();
        cacheManager.setCaffeine(caffeine);
        return cacheManager;
    }

    /**
     * 手动清除指定组的权限缓存
     * 
     * 当WeSpringAuthServer中的组权限配置发生变化时，
     * 可以调用此方法来清除相应的缓存。
     * 
     * @param groupName 组名
     */
    @CacheEvict(value = "groupAuthorities", key = "#groupName")
    public void evictGroupAuthorities(String groupName) {
        logger.info("Evicting cache for group: {}", groupName);
    }

    /**
     * 清除所有组权限缓存
     * 
     * 当需要刷新所有缓存时使用。
     */
    @CacheEvict(value = "groupAuthorities", allEntries = true)
    public void evictAllGroupAuthorities() {
        logger.info("Evicting all group authorities cache");
    }
} 