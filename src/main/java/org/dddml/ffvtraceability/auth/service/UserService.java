package org.dddml.ffvtraceability.auth.service;

import org.dddml.ffvtraceability.auth.config.PasswordTokenProperties;
import org.dddml.ffvtraceability.auth.dto.PreRegisterUserDto;
import org.dddml.ffvtraceability.auth.dto.PreRegisterUserResponse;
import org.dddml.ffvtraceability.auth.dto.UserDto;
import org.dddml.ffvtraceability.auth.exception.BusinessException;
import org.dddml.ffvtraceability.auth.mapper.GroupDtoMapper;
import org.dddml.ffvtraceability.auth.mapper.UserDtoMapper;
import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.dddml.ffvtraceability.auth.util.OffsetDateTimeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.util.*;

@Service
public class UserService {
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    private static final String ALLOWED_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final int OTP_LENGTH = 6;

    private final JdbcTemplate jdbcTemplate;
    private final PasswordEncoder passwordEncoder;
    private final SecureRandom random;
    //@Autowired
    private final PasswordTokenProperties passwordTokenProperties;
    @Autowired
    private PasswordTokenService passwordTokenService;
    @Autowired
    private EmailService emailService;

    public UserService(JdbcTemplate jdbcTemplate, PasswordEncoder passwordEncoder, PasswordTokenProperties passwordTokenProperties) {
        this.jdbcTemplate = jdbcTemplate;
        this.passwordEncoder = passwordEncoder;
        this.random = new SecureRandom();
        this.passwordTokenProperties = passwordTokenProperties;
    }

    public void sendCreatePasswordEmail(String mailTo, String token) {
        String sbLink = passwordTokenProperties.getCreatePasswordUrl() + "?" + "token=" + token + "&type=register";
        String sbHtml = """
                <div style="max-width: 600px; padding: 46px; background: white; outline: 1px #D4D4D8 solid; margin: 0 auto; font-family: Inter;">
                <img style="width: 165px; height: 50px;" src="cid:logo" alt="Logo">
                <div style="margin: 24px 0;">
                <h1 style="font-size: 24px; font-weight: 600; margin: 0 0 8px 0;">Finish Setting up Your Account</h1>
                <p style="font-size: 16px; line-height: 24px; margin: 0;">Use the link below to complete your account setup. It is valid for """ + " " + passwordTokenProperties.getExpireInHours() + " " +
                """ 
                        hours.<br> If it expires, contact the admin to request a new one.</p>
                        </div>
                        <a href='""" +
                sbLink +
                """
                        ' target='_blank'
                            style="display: inline-block;
                            padding: 8px 16px;
                            background: #15803D;
                            color: #FFFFFF;
                            text-decoration: none;
                            border-radius: 4px;
                            font-size: 16px;
                            line-height: 24px;
                            margin: 16px 0;">
                            Finish set-up
                            </a>
                          <hr style="border: 0;
                                    height: 0;
                                    border-top: 1px solid #D4D4D8;
                                    margin: 24px 0;">
                          <div style="text-align: center; margin-top: 24px;">
                              <span style="font-size: 14px;">Powered by</span>
                              <img style="width: 96px; height: 28px; vertical-align: middle;" src="cid:blueforce" alt="Blueforce">
                          </div>
                        </div>
                        """;
//        sbHtml.append("<br><br><a href='");
//        sbHtml.append(sbLink.toString()).append("'>").append(sbLink.toString()).append("</a>");
        Map<String, ClassPathResource> inlineResources = new HashMap<>();
        inlineResources.put("logo", new ClassPathResource("images/logo.png"));
        inlineResources.put("blueforce", new ClassPathResource("images/blueforce.png"));
        emailService.sendHtmlMail(mailTo, "Finish Setting up Your Account", sbHtml, inlineResources);
    }

    @Transactional(readOnly = true)
    public UserDto getUserByUsername(String username) {
        String sql = "SELECT * FROM users WHERE username = ?";
        UserDto user = jdbcTemplate.query(sql, new UserDtoMapper(), username).stream().findFirst().orElse(null);
        //UserDto user = jdbcTemplate.queryForObject(sql, new UserDtoMapper(), username);
        //注释掉的这个写法当遇到没有结果时会报异常EmptyResultDataAccessException
        if (user != null) {
            sql = "select * from groups where id in (select group_id from group_members gm where gm.username=?)";
            user.setGroups(jdbcTemplate.query(sql, new GroupDtoMapper(), username));

            // 获取用户关联的所有组的权限集合
            String sqlAuthorities = """
                        SELECT DISTINCT ad.authority_id
                        FROM authority_definitions ad
                        JOIN group_authorities ga ON ad.authority_id = ga.authority
                        JOIN group_members gm ON ga.group_id = gm.group_id
                        WHERE gm.username = ?
                    """;
            List<String> authorities = jdbcTemplate.queryForList(sqlAuthorities, String.class, username);
            user.setAuthorities(authorities);
        }
        return user;
    }

    /**
     * 给指定用户重新生成密码
     *
     * @param username
     * @param operator
     * @return
     */
    @Transactional
    public PreRegisterUserResponse reGeneratePassword(String username, String operator) {
        String sql = "SELECT * FROM users WHERE username = ?";
        UserDto user = jdbcTemplate.query(sql, new UserDtoMapper(), username).stream().findFirst().orElse(null);
        if (user == null) {
            throw new BusinessException("User not found: " + username);
        }
        String oneTimePassword = generateOneTimePassword();
        String encodedPassword = passwordEncoder.encode(oneTimePassword);
        OffsetDateTime now = OffsetDateTime.now();
        jdbcTemplate.update("""
                UPDATE users SET 
                password = ?,
                password_change_required = true, 
                temp_password_last_generated = ?,
                updated_by = ?,
                updated_at = ?
                WHERE username = ?
                """, encodedPassword, now, operator, now, username);
        return new PreRegisterUserResponse(username, oneTimePassword, now);
    }

    @Transactional
    public PreRegisterUserResponse preRegisterUser(PreRegisterUserDto preRegisterUser, String operator) {
        // Check if user already exists
        String username = preRegisterUser.getUsername();
        if (userExists(username)) {
            throw new BusinessException("User email already exists: " + username);
        }

        // Generate one-time password
        String oneTimePassword = generateOneTimePassword();
        String encodedPassword = passwordEncoder.encode(oneTimePassword);

        OffsetDateTime now = OffsetDateTime.now();
        // Insert new user
        jdbcTemplate.update("INSERT INTO users (username, password, enabled, password_change_required,temp_password_last_generated, first_login,first_name,last_name," + "email,department_id,from_date,employee_number,employee_contract_number,certification_description,skill_set_description," + "language_skills,associated_gln,profile_image_url,direct_manager_name,employee_type_id,telephone_number," + "mobile_number,created_at,updated_at,created_by,updated_by)" + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", username, encodedPassword, true, true, now, true, preRegisterUser.getFirstName(), preRegisterUser.getLastName(), preRegisterUser.getEmail(), preRegisterUser.getDepartmentId(), preRegisterUser.getFromDate(), preRegisterUser.getEmployeeNumber(), preRegisterUser.getEmployeeContractNumber(), preRegisterUser.getCertificationDescription(), preRegisterUser.getSkillSetDescription(), preRegisterUser.getLanguageSkills(), preRegisterUser.getAssociatedGln(), preRegisterUser.getProfileImageUrl(), preRegisterUser.getDirectManagerName(), preRegisterUser.getEmployeeTypeId(), preRegisterUser.getTelephoneNumber(), preRegisterUser.getMobileNumber(), now, now, operator, operator);
        if (preRegisterUser.getGroupIds() == null) {
            preRegisterUser.setGroupIds(new ArrayList<>());
        }
        List<Long> groupIds = preRegisterUser.getGroupIds().stream().distinct().toList();
        if (!groupIds.isEmpty()) {
            groupIds.forEach(groupId -> {
                jdbcTemplate.update("INSERT INTO group_members (username, group_id) values(?,?)", username, groupId);
            });
        } else {
            // 如果 groupIds 为空那么至少要 Add to USER_GROUP
            jdbcTemplate.update("INSERT INTO group_members (username, group_id) SELECT ?, id FROM groups WHERE group_name = 'USER_GROUP'", username);
        }
        String token = UUID.randomUUID().toString();
        passwordTokenService.saveAuthorizationToken(username, token, "register", now);
        sendCreatePasswordEmail(username, token);
        logger.info("Pre-registered user: {}", username);
        return new PreRegisterUserResponse(username, oneTimePassword, now);
    }

    /**
     * Create a new user for social login (WeChat or SMS)
     *
     * @param userDto  The user information
     * @param password The password (will be encoded)
     * @return The created user's username
     */
    @Transactional
    public String createUser(UserDto userDto, String password) {
        return createUser(userDto, password, null);
    }

    /**
     * Create a new user for social login (WeChat or SMS) with referrer support
     *
     * @param userDto   The user information
     * @param password  The password (will be encoded)
     * @param referrerId The referrer ID for promotion scenarios
     * @return The created user's username
     */
    @Transactional
    public String createUser(UserDto userDto, String password, String referrerId) {
        String username = userDto.getUsername();
        if (userExists(username)) {
            throw new BusinessException("User already exists: " + username);
        }

        String encodedPassword = passwordEncoder.encode(password);
        OffsetDateTime now = OffsetDateTime.now();

        // Insert new user with referrer_id support
        jdbcTemplate.update("""
                        INSERT INTO users (
                            username, password, enabled, password_change_required, 
                            first_login, temp_password_last_generated, first_name, last_name,
                            email, mobile_number, profile_image_url, referrer_id, created_at, updated_at
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                username, encodedPassword,
                userDto.getEnabled() != null ? userDto.getEnabled() : true,
                false, false, now,
                userDto.getFirstName(), userDto.getLastName(),
                userDto.getEmail(), userDto.getMobileNumber(),
                userDto.getProfileImageUrl(), referrerId, now, now);

        // Assign default group (USER_GROUP)
        jdbcTemplate.update("""
                INSERT INTO group_members (username, group_id)
                SELECT ?, id FROM groups WHERE group_name = 'USER_GROUP'
                """, username);

        return username;
    }

    public boolean userExists(String username) {
        Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users WHERE username = ?", Integer.class, username);
        return count > 0;
    }

    /**
     * 获取用户当前的手机号
     * 
     * @param username 用户名
     * @return 当前手机号，如果没有则返回null
     */
    @Transactional(readOnly = true)
    public String getCurrentMobileNumber(String username) {
        try {
            String sql = "SELECT mobile_number FROM users WHERE username = ?";
            return jdbcTemplate.queryForObject(sql, String.class, username);
        } catch (Exception e) {
            logger.debug("Failed to get mobile number for user: {}", username);
            return null;
        }
    }

    /**
     * 更新用户的手机号
     * 
     * @param username 用户名  
     * @param mobileNumber 新的手机号
     */
    @Transactional
    public void updateUserMobileNumber(String username, String mobileNumber) {
        String sql = """
                UPDATE users 
                SET mobile_number = ?, updated_at = ? 
                WHERE username = ?
                """;
        OffsetDateTime now = OffsetDateTime.now();
        int rowsUpdated = jdbcTemplate.update(sql, mobileNumber, now, username);
        
        if (rowsUpdated > 0) {
            logger.debug("Successfully updated mobile_number for user: {}", username);
        } else {
            logger.warn("No rows updated when setting mobile_number for user: {}", username);
        }
    }

    private String generateOneTimePassword() {
        StringBuilder sb = new StringBuilder(OTP_LENGTH);
        for (int i = 0; i < OTP_LENGTH; i++) {
            sb.append(ALLOWED_CHARS.charAt(random.nextInt(ALLOWED_CHARS.length())));
        }
        return sb.toString();
    }


    @Transactional(readOnly = true)
    public CustomUserDetails getUserDetails(String username) {
        String queryUser = """
                SELECT u.username, u.password, u.enabled, u.password_change_required, u.password_last_changed, u.first_login, u.mobile_number
                FROM users u
                WHERE u.username = ?
                """;
        Map<String, Object> userInfo = null;
        try {
            userInfo = jdbcTemplate.queryForMap(queryUser, username);
        } catch (Exception exception) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        // 获取用户的直接权限（不包括组权限）
        // 修复说明：之前的重构错误地将组权限包含在用户直接权限中，违反了设计原则
        // 我们的设计是将用户的"直接权限"和"组权限"在JWT中分开，防止JWT过大
        // 组权限应该通过JWT中的"groups"声明在资源服务器端动态获取
        String sqlAuthorities = """
                    SELECT DISTINCT a.authority
                    FROM authorities a
                    WHERE a.username = ?
                """;
        List<String> authorities;
        try {
            authorities = jdbcTemplate.queryForList(sqlAuthorities, String.class, username);
        } catch (Exception exception) {
            logger.error("Failed to load direct authorities for user: {}", username, exception);
            authorities = new ArrayList<>();
        }

        // 获取用户所属的组
        List<String> groupNames;
        try {
            groupNames = jdbcTemplate.queryForList("""
                            select
                            group_name
                            from groups
                            where id in (select group_id from group_members gm where gm.username=?)
                            and enabled is true
                            """,
                    String.class, username);
        } catch (Exception e) {
            groupNames = new ArrayList<>();
        }

        Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
        List<String> groups = new ArrayList<>(groupNames);
        for (String authority : authorities) {
            grantedAuthorities.add(new SimpleGrantedAuthority(authority));
        }
        
        // 添加调试日志
        logger.debug("User {} loaded with direct authorities: {}", username, authorities);
        logger.debug("User {} loaded with groups: {}", username, groupNames);
        OffsetDateTime passwordLastChanged = OffsetDateTimeUtil.toOffsetDateTime(userInfo.get("password_last_changed"));

        // 🔑 获取手机号并设置到CustomUserDetails中
        String mobileNumber = (String) userInfo.get("mobile_number");
        logger.debug("User {} loaded with mobile number: {}", username, mobileNumber != null ? mobileNumber.substring(0, 3) + "****" : null);

        return new CustomUserDetails(
                username,
                (String) userInfo.get("password"),
                userInfo.get("enabled") != null && (Boolean) userInfo.get("enabled"),
                true, // accountNonExpired
                true, // credentialsNonExpired  
                true, // accountNonLocked
                grantedAuthorities,
                Collections.emptyMap(), // additionalDetails
                groups,
                mobileNumber, // 🔑 设置手机号到phoneNumber字段
                (Boolean) userInfo.get("password_change_required"),
                passwordLastChanged,
                (Boolean) userInfo.get("first_login")
        );
    }
}