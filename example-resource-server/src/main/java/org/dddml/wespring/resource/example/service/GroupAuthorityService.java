package org.dddml.wespring.resource.example.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

/**
 * 组权限服务
 * 
 * 负责从数据库查询组对应的权限定义。
 * 使用缓存来提高性能，避免频繁的数据库查询。
 * 
 * 这个服务需要访问与WeSpringAuthServer相同的数据库（或同步的从库），
 * 以便获取最新的组权限配置。
 */
@Service
public class GroupAuthorityService {
    
    private static final Logger logger = LoggerFactory.getLogger(GroupAuthorityService.class);
    
    @Autowired
    @Qualifier("securityJdbcTemplate") // 使用安全相关的数据源
    private JdbcTemplate securityJdbcTemplate;
    
    /**
     * 获取指定组的所有权限
     * 
     * @param groupName 组名（包含GROUP_前缀）
     * @return 该组拥有的所有权限集合
     */
    @Cacheable(value = "groupAuthorities", key = "#groupName")
    public Set<String> getGroupAuthorities(String groupName) {
        logger.info("Cache MISS - Loading authorities from database for group: {}", groupName);
        
        // 查询组权限的SQL（基于生产环境的实际实现）
        // group_authorities表直接存储权限字符串，无需关联authority_definitions表
        String sql = """
            SELECT authority 
            FROM group_authorities ga 
            JOIN groups g ON ga.group_id = g.id 
            WHERE g.group_name = ?
            """;
            
        Set<String> authorities = new HashSet<>(securityJdbcTemplate.queryForList(sql, String.class,
            groupName.replace("GROUP_", "")));
        
        logger.debug("Loaded {} authorities from database for group: {}", authorities.size(), groupName);
        return authorities;
    }
} 