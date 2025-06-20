package org.dddml.wespring.resource.example.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

/**
 * 数据源配置
 * 
 * 这个配置类展示了如何配置多个数据源：
 * 1. 业务数据源 - 用于应用的业务数据
 * 2. 安全数据源 - 用于访问WeSpringAuthServer的用户权限数据
 * 
 * 在实际应用中，你可能需要：
 * - 使用相同的数据库（如果资源服务器和授权服务器共享数据库）
 * - 使用从库（如果使用主从复制）
 * - 使用不同的数据库（如果权限数据通过其他方式同步）
 */
@Configuration
public class DataSourceConfig {

    /**
     * 业务数据源配置属性
     */
    @Primary
    @Bean
    @ConfigurationProperties("spring.datasource")
    public DataSourceProperties businessDataSourceProperties() {
        return new DataSourceProperties();
    }

    /**
     * 安全数据源配置属性
     * 用于访问WeSpringAuthServer的权限数据
     */
    @Bean
    @ConfigurationProperties("spring.security.datasource")
    public DataSourceProperties securityDataSourceProperties() {
        return new DataSourceProperties();
    }

    /**
     * 业务数据源
     */
    @Primary
    @Bean
    public DataSource businessDataSource(
            @Qualifier("businessDataSourceProperties") DataSourceProperties properties) {
        return properties.initializeDataSourceBuilder().build();
    }

    /**
     * 安全数据源
     * 连接到WeSpringAuthServer的数据库以获取权限信息
     */
    @Bean
    public DataSource securityDataSource(
            @Qualifier("securityDataSourceProperties") DataSourceProperties properties) {
        return properties.initializeDataSourceBuilder().build();
    }

    /**
     * 业务JdbcTemplate
     */
    @Primary
    @Bean
    public JdbcTemplate jdbcTemplate(@Qualifier("businessDataSource") DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }

    /**
     * 安全JdbcTemplate
     * 用于查询WeSpringAuthServer的权限数据
     */
    @Bean
    public JdbcTemplate securityJdbcTemplate(@Qualifier("securityDataSource") DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }
} 