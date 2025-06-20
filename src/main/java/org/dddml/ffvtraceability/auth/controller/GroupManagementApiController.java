package org.dddml.ffvtraceability.auth.controller;

import org.dddml.ffvtraceability.auth.dto.GroupDto;
import org.dddml.ffvtraceability.auth.exception.BusinessException;
import org.dddml.ffvtraceability.auth.mapper.GroupDtoMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.sql.PreparedStatement;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping({"/auth-srv/groups", "/api/groups"})
public class GroupManagementApiController {
    private static final Logger logger = LoggerFactory.getLogger(GroupManagementApiController.class);

    private final JdbcTemplate jdbcTemplate;

    public GroupManagementApiController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping
    @Transactional(readOnly = true)
    public List<GroupDto> findGroups(@RequestParam(value = "enabled", required = false) Boolean enabled) {
        List<GroupDto> groups = null;
        StringBuilder sql = new StringBuilder("SELECT * FROM groups");
        if (enabled != null) {
            sql.append(" WHERE enabled = ? order by id");
            groups = jdbcTemplate.query(sql.toString(), new GroupDtoMapper(), enabled);
        } else {
            sql.append(" order by id");
            groups = jdbcTemplate.query(sql.toString(), new GroupDtoMapper());
        }
        groups.forEach(group -> {
            String sqlGetAuthorities = """
                    SELECT ga.authority 
                    FROM group_authorities ga
                    JOIN authority_definitions ad ON ga.authority = ad.authority_id
                    WHERE ga.group_id = ? 
                    AND (ad.enabled IS NULL OR ad.enabled = true)
                    """;
            group.setAuthorities(jdbcTemplate.queryForList(sqlGetAuthorities, String.class, group.getId()));
        });
        return groups;
    }

    @GetMapping("/list")
    @Transactional(readOnly = true)
    public List<Map<String, Object>> getGroups() {
        String sql = """
                SELECT g.id, g.group_name, g.enabled,
                        STRING_AGG(DISTINCT u.username, ', ') as members,
                COUNT(DISTINCT gm.username) as member_count,
                STRING_AGG(DISTINCT ga.authority, ', ') as authorities
                FROM groups g
                LEFT JOIN group_members gm ON g.id = gm.group_id
                LEFT JOIN users u ON gm.username = u.username
                LEFT JOIN group_authorities ga ON g.id = ga.group_id
                GROUP BY g.id, g.group_name, g.enabled
                ORDER BY g.group_name
                """;
        return jdbcTemplate.queryForList(sql);
    }

    @GetMapping("/{groupId}/members")
    @Transactional(readOnly = true)
    public List<String> getGroupMembers(@PathVariable Long groupId) {
        return jdbcTemplate.queryForList(
                "SELECT username FROM group_members WHERE group_id = ? ORDER BY username",
                String.class,
                groupId
        );
    }

    @GetMapping("/available-users")
    @Transactional(readOnly = true)
    public List<Map<String, Object>> getAvailableUsers(
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "20") int limit) {
        // 构建搜索条件
        String searchCondition = "";
        java.util.List<Object> searchParams = new java.util.ArrayList<>();
        if (search != null && !search.trim().isEmpty()) {
            searchCondition = """
                AND (u.username ILIKE ? OR EXISTS (
                    SELECT 1 FROM user_identifications ui2 
                    WHERE ui2.username = u.username 
                    AND ui2.identifier ILIKE ?
                ))
                """;
            String searchPattern = "%" + search.trim() + "%";
            searchParams.add(searchPattern);
            searchParams.add(searchPattern);
        }
        
        // 限制最大返回数量
        if (limit > 100) limit = 100;
        if (limit < 1) limit = 20;
        
        String sql = """
                SELECT u.username,
                       STRING_AGG(DISTINCT 
                           CASE WHEN ui.user_identification_type_id IS NOT NULL THEN
                               ui.user_identification_type_id || ':' || ui.identifier || '|' || COALESCE(ui.verified::text, 'null')
                           END, ', ') as identifications
                FROM users u
                LEFT JOIN user_identifications ui ON u.username = ui.username
                WHERE u.username != '*'
                """ + searchCondition + """
                GROUP BY u.username
                ORDER BY u.username
                LIMIT ?
                """;
        
        List<Map<String, Object>> users;
        searchParams.add(limit);
        users = jdbcTemplate.queryForList(sql, searchParams.toArray());
        
        // 处理标识数据，借鉴用户管理页面的格式化逻辑
        users.forEach(user -> {
            String rawIdentifications = (String) user.get("identifications");
            if (rawIdentifications != null) {
                user.put("identifications", formatIdentifications(rawIdentifications));
                user.put("displayName", formatUserDisplayName((String) user.get("username"), rawIdentifications));
            } else {
                user.put("displayName", user.get("username"));
            }
        });
        
        return users;
    }
    
    private String formatIdentifications(String rawIdentifications) {
        if (rawIdentifications == null || rawIdentifications.trim().isEmpty()) {
            return null;
        }
        
        return java.util.Arrays.stream(rawIdentifications.split(", "))
                .map(this::formatSingleIdentification)
                .collect(java.util.stream.Collectors.joining(", "));
    }

    private String formatSingleIdentification(String identification) {
        String[] parts = identification.split("\\|");
        if (parts.length != 2) {
            return identification; // fallback
        }
        
        String typeAndValue = parts[0];
        String verifiedStatus = parts[1];
        
        // 脱敏处理
        String maskedIdentification = maskSensitiveIdentification(typeAndValue);
        
        // 验证状态处理：只有明确为false才显示警告，null不显示符号
        if ("true".equals(verifiedStatus)) {
            return maskedIdentification + "✓";
        } else if ("false".equals(verifiedStatus)) {
            return maskedIdentification + "⚠";
        } else {
            // verified为null的情况，不显示符号
            return maskedIdentification;
        }
    }

    private String maskSensitiveIdentification(String typeAndValue) {
        String[] parts = typeAndValue.split(":", 2);
        if (parts.length != 2) {
            return typeAndValue;
        }
        
        String type = parts[0];
        String value = parts[1];
        String maskedValue = maskSensitiveValue(type, value);
        
        return type + ":" + maskedValue;
    }

    private String maskSensitiveValue(String identificationType, String identifier) {
        // 统一转换为大写进行匹配，因为系统中的标识类型都是大写
        String upperType = identificationType.toUpperCase();
        
        switch (upperType) {
            // 手机号相关（需要脱敏）
            case "MOBILE":
            case "PHONE":
            case "MOBILE_NUMBER":
            case "WECHAT_MOBILE_NUMBER":
                // 手机号脱敏：139****8888
                if (identifier.length() >= 7) {
                    return identifier.substring(0, 3) + "****" + identifier.substring(identifier.length() - 4);
                }
                break;
                
            // 身份证号（需要脱敏）
            case "ID_CARD":
            case "IDENTITY_CARD":
                // 身份证脱敏：110***********1234
                if (identifier.length() >= 8) {
                    return identifier.substring(0, 3) + "***********" + identifier.substring(identifier.length() - 4);
                }
                break;
                
            // 邮箱（需要脱敏）
            case "EMAIL":
                // 邮箱脱敏：abc***@example.com
                int atIndex = identifier.indexOf('@');
                if (atIndex > 3) {
                    return identifier.substring(0, 3) + "***" + identifier.substring(atIndex);
                }
                break;
                
            // 微信相关（不脱敏，管理员需要看到完整信息以便调试）
            case "WECHAT_OPENID":
            case "WECHAT_UNIONID":
                return identifier;
                
            default:
                // 其他未知类型保持原样显示
                return identifier;
        }
        return identifier;
    }
    
    private String formatUserDisplayName(String username, String rawIdentifications) {
        if (rawIdentifications == null || rawIdentifications.trim().isEmpty()) {
            return username;
        }
        
        // 按优先级选择最佳的可读标识
        String[] identifications = rawIdentifications.split(", ");
        String bestReadableId = getBestReadableIdentification(identifications);
        
        if (bestReadableId != null) {
            return username + " (" + bestReadableId + ")";
        }
        
        return username;
    }
    
    private String getBestReadableIdentification(String[] identifications) {
        String phoneNumber = null;
        String email = null;
        
        for (String identification : identifications) {
            String[] parts = identification.split("\\|");
            if (parts.length != 2) continue;
            
            String typeAndValue = parts[0];
            String[] typeValueParts = typeAndValue.split(":", 2);
            if (typeValueParts.length != 2) continue;
            
            String type = typeValueParts[0].toUpperCase();
            String value = typeValueParts[1];
            
            // 优先选择手机号
            if (("MOBILE_NUMBER".equals(type) || "WECHAT_MOBILE_NUMBER".equals(type)) && phoneNumber == null) {
                phoneNumber = maskSensitiveValue(type, value);
            }
            // 其次选择邮箱
            else if ("EMAIL".equals(type) && email == null) {
                email = maskSensitiveValue(type, value);
            }
        }
        
        // 返回优先级最高的可读标识
        return phoneNumber != null ? phoneNumber : email;
    }

    @PostMapping("/create")
    @Transactional
    public Map<String, Object> createGroup(@RequestBody Map<String, String> request) {
        String groupName = request.get("groupName");
        if (groupName == null || groupName.isBlank()) {
            throw new IllegalArgumentException("Group name can't be null");
        }
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM groups WHERE group_name = ?",
                Integer.class,
                groupName
        );
        if (count > 0) {
            throw new BusinessException("Group name already exists: " + groupName);
        }
        String description = request.get("description");

//        try {
        logger.debug("Attempting to create group with name: {},description:{}", groupName, description);

        KeyHolder keyHolder = new GeneratedKeyHolder();
        int rows = jdbcTemplate.update(connection -> {
            PreparedStatement ps = connection.prepareStatement(
                    "INSERT INTO groups (group_name,description) VALUES (?,?)",
                    new String[]{"id"}
            );
            ps.setString(1, groupName);
            ps.setString(2, description);
            return ps;
        }, keyHolder);

        if (rows == 0) {
            logger.error("No rows were inserted for group: {}", groupName);
            throw new BusinessException("Failed to create group - no rows inserted");
        }

        Number key = keyHolder.getKey();
        if (key == null) {
            logger.error("Failed to get generated key for group: {}", groupName);
            throw new BusinessException("Failed to create group - no generated key");
        }

        Map<String, Object> response = Map.of(
                "id", key.longValue(),
                "groupName", groupName,
                "description", description
        );

        logger.debug("Successfully created group: {}, with ID: {}", groupName, key.longValue());
        return response;

//        } catch (Exception e) {
//            logger.error("Failed to create group: {} - {}", groupName, e.getMessage());
//            if (e.getMessage() != null && e.getMessage().contains("duplicate key value")) {
//                return ResponseEntity.badRequest().body("Group name already exists");
//            }
//            return ResponseEntity.badRequest().body("Failed to create group: " + e.getMessage());
//        }
    }

    @PostMapping("/{groupId}/members")
    @Transactional
    public void addGroupMember(@PathVariable Long groupId, @RequestBody Map<String, String> request) {
        String username = request.get("username");
        jdbcTemplate.update(
                "INSERT INTO group_members (group_id, username) VALUES (?, ?) ON CONFLICT DO NOTHING",
                groupId, username
        );
    }

    @DeleteMapping("/{groupId}/members/{username}")
    @Transactional
    public void removeGroupMember(@PathVariable Long groupId, @PathVariable String username) {
        jdbcTemplate.update(
                "DELETE FROM group_members WHERE group_id = ? AND username = ?",
                groupId, username
        );
    }

    @PostMapping("/{groupId}/toggle-enabled")
    @Transactional
    public void toggleGroupEnabled(@PathVariable Long groupId) {
        // 首先检查是否是 ADMIN_GROUP，不允许禁用
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM groups WHERE id = ? AND group_name = 'ADMIN_GROUP'",
                Integer.class,
                groupId
        );

        if (count != null && count > 0) {
            throw new BusinessException("Cannot disable ADMIN_GROUP");
        }

        // 切换状态
        int rows = jdbcTemplate.update(
                "UPDATE groups SET enabled = NOT enabled WHERE id = ?",
                groupId
        );

        if (rows == 0) {
            throw new BusinessException("Group not found");
        }
        // 如果组被禁用，同时删除所有组成员关系
        jdbcTemplate.update(
                "DELETE FROM group_members WHERE group_id = ? AND EXISTS (SELECT 1 FROM groups WHERE id = ? AND enabled = false)",
                groupId, groupId
        );

    }
}