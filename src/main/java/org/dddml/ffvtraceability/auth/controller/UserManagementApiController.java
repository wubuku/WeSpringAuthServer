package org.dddml.ffvtraceability.auth.controller;

import org.dddml.ffvtraceability.auth.dto.UserDto;
import org.dddml.ffvtraceability.auth.exception.BusinessException;
import org.dddml.ffvtraceability.auth.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping({"/auth-srv/users", "/api/users"})
public class UserManagementApiController {
    private static final Logger logger = LoggerFactory.getLogger(UserManagementApiController.class);

    private final JdbcTemplate jdbcTemplate;
    private final UserService userService;

    public UserManagementApiController(JdbcTemplate jdbcTemplate, UserService userService) {
        this.jdbcTemplate = jdbcTemplate;
        this.userService = userService;
    }

    @GetMapping("/list")
    @Transactional(readOnly = true)
    public Map<String, Object> getUsers(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String search) {
        
        // 验证分页参数
        if (page < 1) page = 1;
        if (size < 1) size = 10;
        if (size > 100) size = 100; // 限制最大页大小
        
        // 计算偏移量
        int offset = (page - 1) * size;
        
        // 构建搜索条件
        String searchCondition = "";
        java.util.List<Object> searchParams = new java.util.ArrayList<>();
        if (search != null && !search.trim().isEmpty()) {
            searchCondition = """
                AND (u.username ILIKE ? OR EXISTS (
                    SELECT 1 FROM user_identifications ui 
                    WHERE ui.username = u.username 
                    AND ui.identifier ILIKE ?
                ))
                """;
            String searchPattern = "%" + search.trim() + "%";
            searchParams.add(searchPattern);
            searchParams.add(searchPattern);
        }
        
        // 先查询总数
        String countSql = """
                SELECT COUNT(DISTINCT u.username)
                FROM users u
                WHERE u.username != '*'
                """ + searchCondition;
        
        int totalCount;
        if (searchParams.isEmpty()) {
            totalCount = jdbcTemplate.queryForObject(countSql, Integer.class);
        } else {
            totalCount = jdbcTemplate.queryForObject(countSql, Integer.class, searchParams.toArray());
        }
        
        // 查询分页数据
        String sql = """
                SELECT u.username, u.enabled, u.password_change_required,
                       STRING_AGG(DISTINCT g.group_name, ', ') as groups,
                       STRING_AGG(DISTINCT a.authority, ', ') as authorities,
                       STRING_AGG(DISTINCT 
                           CASE WHEN ui.user_identification_type_id IS NOT NULL THEN
                               ui.user_identification_type_id || ':' || ui.identifier || '|' || COALESCE(ui.verified::text, 'null')
                           END, ', ') as identifications
                FROM users u
                LEFT JOIN group_members gm ON u.username = gm.username
                LEFT JOIN groups g ON gm.group_id = g.id
                LEFT JOIN authorities a ON u.username = a.username
                LEFT JOIN user_identifications ui ON u.username = ui.username
                WHERE u.username != '*'
                """ + searchCondition + """
                GROUP BY u.username, u.enabled, u.password_change_required
                ORDER BY u.username
                LIMIT ? OFFSET ?
                """;

        List<Map<String, Object>> users;
        java.util.List<Object> allParams = new java.util.ArrayList<>(searchParams);
        allParams.add(size);
        allParams.add(offset);
        users = jdbcTemplate.queryForList(sql, allParams.toArray());
        
        // 处理标识数据
        users.forEach(user -> {
            String rawIdentifications = (String) user.get("identifications");
            if (rawIdentifications != null) {
                user.put("identifications", formatIdentifications(rawIdentifications));
            }
        });
        
        // 计算总页数
        int totalPages = (int) Math.ceil((double) totalCount / size);
        
        // 返回分页结果
        Map<String, Object> result = new java.util.HashMap<>();
        result.put("users", users);
        result.put("currentPage", page);
        result.put("pageSize", size);
        result.put("totalCount", totalCount);
        result.put("totalPages", totalPages);
        result.put("hasNext", page < totalPages);
        result.put("hasPrevious", page > 1);
        
        return result;
    }


    @GetMapping("/{username}")
    @Transactional(readOnly = true)
    public UserDto getUserByUserName(@PathVariable("username") String username) {
        return userService.getUserByUsername(username);
    }

    @PostMapping("/{username}/toggle-enabled")
    @Transactional
    public void toggleEnabled(@PathVariable String username) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = auth.getName();

        if (username.equals(currentUsername)) {
            throw new BusinessException("Cannot disable your own account");
        }
        jdbcTemplate.update(
                "UPDATE users SET enabled = NOT enabled WHERE username = ?",
                username
        );
    }

    @PostMapping("/{username}/toggle-password-change")
    public void togglePasswordChange(@PathVariable String username) {
        jdbcTemplate.update(
                "UPDATE users SET password_change_required = NOT password_change_required WHERE username = ?",
                username
        );
    }

    private String formatIdentifications(String rawIdentifications) {
        if (rawIdentifications == null || rawIdentifications.trim().isEmpty()) {
            return null;
        }
        
        return Arrays.stream(rawIdentifications.split(", "))
                .map(this::formatSingleIdentification)
                .collect(Collectors.joining(", "));
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
                
            // 未来可能的标识类型（暂时注释，作为举例）
            // case "ALIPAY_OPENID":
            // case "QQ_OPENID":
            // case "DINGTALK_OPENID":
            // case "ENTERPRISE_EMPLOYEE_ID":
            // case "PASSPORT_NUMBER":
            // case "DRIVER_LICENSE":
            //     return identifier; // 根据需要决定是否脱敏
                
            default:
                // 其他未知类型保持原样显示
                return identifier;
        }
        return identifier;
    }
} 