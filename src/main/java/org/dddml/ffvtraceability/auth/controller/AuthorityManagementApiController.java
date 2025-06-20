package org.dddml.ffvtraceability.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.dddml.ffvtraceability.auth.exception.BusinessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping({"/auth-srv/authorities", "/api/authorities"})
public class AuthorityManagementApiController {
    private static final Logger logger = LoggerFactory.getLogger(AuthorityManagementApiController.class);

    private final JdbcTemplate jdbcTemplate;

    @Autowired
    @Qualifier("defaultObjectMapper")
    private ObjectMapper objectMapper;

    public AuthorityManagementApiController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/users")
    @Transactional(readOnly = true)
    public List<Map<String, Object>> getUsers(
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "20") int limit) {
        
        // 验证和限制参数
        if (limit < 1) limit = 20;
        if (limit > 100) limit = 100;
        
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
        
        // 查询用户及其标识信息
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
        
        java.util.List<Object> allParams = new java.util.ArrayList<>(searchParams);
        allParams.add(limit);
        
        List<Map<String, Object>> users = jdbcTemplate.queryForList(sql, allParams.toArray());
        
        // 处理标识数据
        users.forEach(user -> {
            String rawIdentifications = (String) user.get("identifications");
            if (rawIdentifications != null) {
                user.put("identifications", formatIdentifications(rawIdentifications));
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
                int atIndex = identifier.indexOf('@');
                if (atIndex > 3) {
                    return identifier.substring(0, 3) + "***" + identifier.substring(atIndex);
                }
                break;
                
            // 微信相关标识（不脱敏，便于管理员调试）
            case "WECHAT_OPENID":
            case "WECHAT_UNIONID":
                return identifier;
        }
        
        // 默认情况，不脱敏或简单脱敏
        return identifier;
    }

    @GetMapping("/base")
    @Transactional(readOnly = true)
    public List<Map<String, Object>> getBaseAuthorities() {
        logger.debug("Fetching base authorities...");
        String sql = """
                SELECT authority_id, description, enabled 
                FROM authority_definitions 
                ORDER BY authority_id
                """;
        List<Map<String, Object>> authorities = jdbcTemplate.queryForList(sql);
        logger.debug("Found {} base authorities: {}", authorities.size(), authorities);
        return authorities;
    }

    @GetMapping("/user/{username}")
    @Transactional(readOnly = true)
    public List<String> getUserAuthorities(@PathVariable String username) {
        String sql = """
                SELECT a.authority 
                FROM authorities a
                JOIN authority_definitions p ON a.authority = p.authority_id
                WHERE a.username = ? 
                AND (p.enabled IS NULL OR p.enabled = true)
                ORDER BY a.authority
                """;
        return jdbcTemplate.queryForList(sql, String.class, username);
    }

    @PostMapping("/update")
    @Transactional
    public void updateAuthority(@RequestBody Map<String, Object> request) {
        String username = (String) request.get("username");
        String authority = (String) request.get("authority");
        boolean granted = (boolean) request.get("granted");

        if (granted) {
            jdbcTemplate.update(
                    "INSERT INTO authorities (username, authority) VALUES (?, ?) ON CONFLICT DO NOTHING",
                    username, authority
            );
        } else {
            jdbcTemplate.update(
                    "DELETE FROM authorities WHERE username = ? AND authority = ?",
                    username, authority
            );
        }
    }

    @PostMapping("/batch-update")
    @Transactional
    public void batchUpdateAuthorities(@RequestBody Map<String, Object> request) {
        String username = (String) request.get("username");
        @SuppressWarnings("unchecked")
        List<String> authorities = (List<String>) request.get("authorities");
        boolean granted = (boolean) request.get("granted");

        logger.debug("Batch updating authorities for user: {}, granted: {}, authorities: {}",
                username, granted, authorities);

        if (granted) {
            // 批量插入权限
            for (String authority : authorities) {
                jdbcTemplate.update(
                        "INSERT INTO authorities (username, authority) VALUES (?, ?) ON CONFLICT DO NOTHING",
                        username, authority
                );
            }
        } else {
            // 批量删除权限
            jdbcTemplate.batchUpdate(
                    "DELETE FROM authorities WHERE username = ? AND authority = ?",
                    authorities.stream()
                            .map(authority -> new Object[]{username, authority})
                            .collect(Collectors.toList())
            );
        }
    }

    @GetMapping("/groups")
    @Transactional(readOnly = true)
    public List<GroupInfo> getGroups() {
        return jdbcTemplate.query(
                "SELECT id, group_name FROM groups ORDER BY group_name",
                (rs, rowNum) -> new GroupInfo(rs.getLong("id"), rs.getString("group_name"))
        );
    }

    @GetMapping("/group/{groupId}")
    @Transactional(readOnly = true)
    public List<String> getGroupAuthorities(@PathVariable Long groupId) {
        String sql = """
                SELECT ga.authority 
                FROM group_authorities ga
                JOIN authority_definitions p ON ga.authority = p.authority_id
                WHERE ga.group_id = ? 
                AND (p.enabled IS NULL OR p.enabled = true)
                ORDER BY ga.authority
                """;
        return jdbcTemplate.queryForList(sql, String.class, groupId);
    }

    @PostMapping("/group/update")
    @Transactional
    public void updateGroupAuthority(@RequestBody Map<String, Object> request) {
        Long groupId = Long.valueOf(request.get("groupId").toString());
        String authority = (String) request.get("authority");
        boolean granted = (boolean) request.get("granted");

        if (granted) {
            jdbcTemplate.update(
                    "INSERT INTO group_authorities (group_id, authority) VALUES (?, ?) ON CONFLICT DO NOTHING",
                    groupId, authority
            );
        } else {
            jdbcTemplate.update(
                    "DELETE FROM group_authorities WHERE group_id = ? AND authority = ?",
                    groupId, authority
            );
        }
    }

    @PostMapping("/group/batch-update")
    @Transactional
    public void batchUpdateGroupAuthorities(@RequestBody Map<String, Object> request) {
        Long groupId = Long.valueOf(request.get("groupId").toString());
        @SuppressWarnings("unchecked")
        List<String> authorities = (List<String>) request.get("authorities");
        boolean granted = (boolean) request.get("granted");

        logger.debug("Batch updating authorities for group: {}, granted: {}, authorities: {}",
                groupId, granted, authorities);

        if (granted) {
            for (String authority : authorities) {
                jdbcTemplate.update(
                        "INSERT INTO group_authorities (group_id, authority) VALUES (?, ?) ON CONFLICT DO NOTHING",
                        groupId, authority
                );
            }
        } else {
            jdbcTemplate.batchUpdate(
                    "DELETE FROM group_authorities WHERE group_id = ? AND authority = ?",
                    authorities.stream()
                            .map(authority -> new Object[]{groupId, authority})
                            .collect(Collectors.toList())
            );
        }
    }

    @PostMapping("/create")
    @Transactional
    public void createAuthority(@RequestBody Map<String, String> request) {
        String authorityId = request.get("authorityId");
        String description = request.get("description");
        jdbcTemplate.update(
                "INSERT INTO authority_definitions (authority_id, description, enabled) VALUES (?, ?, NULL)",
                authorityId, description
        );
    }

    @PostMapping("/{authorityId}/toggle-enabled")
    @Transactional
    public void toggleAuthorityEnabled(@PathVariable String authorityId) {
        // 先检查当前状态
        Boolean currentEnabled = jdbcTemplate.queryForObject(
                "SELECT enabled FROM authority_definitions WHERE authority_id = ?",
                Boolean.class,
                authorityId
        );

        // 如果当前是 null，设置为 false；如果当前是 false，设置为 null
        Boolean newEnabled = (currentEnabled == null) ? false : null;

        jdbcTemplate.update(
                "UPDATE authority_definitions SET enabled = ? WHERE authority_id = ?",
                newEnabled, authorityId
        );
    }

    @PostMapping("/{authorityId}/update")
    @Transactional
    public void updateAuthority(
            @PathVariable String authorityId,
            @RequestBody Map<String, String> request) {
        String description = request.get("description");

        jdbcTemplate.update(
                "UPDATE authority_definitions SET description = ? WHERE authority_id = ?",
                description, authorityId
        );
    }

    @PostMapping("/import-csv")
    @Transactional
    public String importAuthoritiesFromCsv(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            throw new BusinessException("Please select a file to upload");
        }

        // 文件大小限制：最大1MB
        if (file.getSize() > 1024 * 1024) {
            throw new BusinessException("File size must be less than 1MB");
        }

        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null || !originalFilename.toLowerCase().endsWith(".csv")) {
            throw new BusinessException("Please upload a CSV file");
        }

        // 验证文件名，防止路径遍历攻击
        if (originalFilename.contains("..") || originalFilename.contains("/") || originalFilename.contains("\\")) {
            throw new BusinessException("Invalid filename");
        }

        try (BufferedReader reader
                     = new BufferedReader(new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8));
             CSVParser csvParser = CSVFormat.DEFAULT
                     .builder()
                     .setHeader()
                     .setSkipHeaderRecord(true)
                     .setIgnoreHeaderCase(true)
                     .setTrim(true)
                     .build()
                     .parse(reader)
        ) {
            // 验证必需的列是否存在
            Set<String> headers = new HashSet<>(csvParser.getHeaderNames());
            if (!headers.contains("authority_id")) {
                throw new BusinessException("CSV file must contain 'authority_id' column");
            }

            List<String> errors = new ArrayList<>();
            int lineNumber = 1;
            int successCount = 0;

            for (CSVRecord record : csvParser) {
                lineNumber++;
                try {
                    String authorityId = record.get("authority_id").trim();
                    if (authorityId.isEmpty()) {
                        errors.add(String.format("Line %d: authority_id cannot be empty", lineNumber));
                        continue;
                    }

                    // 获取描述（如果存在）
                    String description = headers.contains("description") ?
                            record.get("description").trim() : null;

                    // 解析 enabled 值（如果存在）
                    Boolean enabled = null;
                    if (headers.contains("enabled")) {
                        String enabledStr = record.get("enabled").trim();
                        if (!enabledStr.isEmpty()) {
                            enabled = parseEnabledValue(enabledStr);
                        }
                    }

                    // 更新或插入权限
                    jdbcTemplate.update("""
                                    INSERT INTO authority_definitions (authority_id, description, enabled)
                                    VALUES (?, ?, ?)
                                    ON CONFLICT (authority_id) DO UPDATE
                                    SET description = EXCLUDED.description,
                                        enabled = EXCLUDED.enabled
                                    """,
                            authorityId, description, enabled
                    );
                    successCount++;

                } catch (Exception e) {
                    errors.add(String.format("Line %d: %s", lineNumber, e.getMessage()));
                }
            }

            // 构建响应消息
            StringBuilder message = new StringBuilder()
                    .append(String.format("Successfully processed %d authorities. ", successCount));
            if (!errors.isEmpty()) {
                message.append(String.format("Found %d errors:\n", errors.size()));
                errors.forEach(error -> message.append(error).append("\n"));
            }

            return message.toString();

        } catch (Exception e) {
            logger.error("Error processing CSV file", e);
            throw new BusinessException("Error processing CSV file. Please check the file format and try again.");
        }
    }

    private Boolean parseEnabledValue(String value) {
        String normalizedValue = value.trim().toUpperCase();
        if (normalizedValue.isEmpty()) {
            return null;
        }

        // 视为 true 的值
        Set<String> trueValues = Set.of(
                "TRUE", "YES", "Y", "1", "T", "ENABLED", "ENABLE"
        );

        // 如果是 true 值返回 null（表示启用），否则返回 false
        return trueValues.contains(normalizedValue) ? null : false;
    }

    // 添加一个新的数据类来表示组信息
    public static class GroupInfo {
        private Long id;
        private String name;

        public GroupInfo(Long id, String name) {
            this.id = id;
            this.name = name;
        }

        public Long getId() {
            return id;
        }

        public String getName() {
            return name;
        }
    }
} 