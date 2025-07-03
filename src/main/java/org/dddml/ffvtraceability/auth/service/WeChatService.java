package org.dddml.ffvtraceability.auth.service;

import cn.binarywang.wx.miniapp.api.WxMaService;
import cn.binarywang.wx.miniapp.bean.WxMaJscode2SessionResult;
import cn.binarywang.wx.miniapp.bean.WxMaPhoneNumberInfo;
import me.chanjar.weixin.common.error.WxErrorException;
import org.dddml.ffvtraceability.auth.dto.UserDto;
import org.dddml.ffvtraceability.auth.dto.UserIdentificationDto;
import org.dddml.ffvtraceability.auth.exception.AuthenticationException;
import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class WeChatService {
    private static final Logger logger = LoggerFactory.getLogger(WeChatService.class);

    // Constants
    private static final String WECHAT_OPENID_TYPE = "WECHAT_OPENID";
    private static final String WECHAT_UNIONID_TYPE = "WECHAT_UNIONID";
    private static final String WECHAT_MOBILE_TYPE = "WECHAT_MOBILE_NUMBER";
    private static final String USERNAME_PREFIX = "wx_";
    private static final int USERNAME_SUFFIX_LENGTH = 20; // Increased from 10 to 20 for better uniqueness
    
    // Import MV_PREFIX from DatabaseSmsVerificationService for consistency
    private static final String MV_PREFIX = DatabaseSmsVerificationService.MV_PREFIX;

    // Error messages
    private static final String ERROR_SESSION_INFO = "Failed to get WeChat session info:";
    private static final String ERROR_MOBILE_INFO = "Failed to get user mobile info:";
    private static final String ERROR_OPENID_EMPTY = "Failed to get WeChat session info: OpenID is empty";
    private static final String ERROR_AUTHENTICATION = "Failed to authenticate with WeChat: ";

    private final WxMaService wxMaService;
    private final UserService userService;
    private final UserIdentificationService userIdentificationService;

    public WeChatService(WxMaService wxMaService, UserService userService, UserIdentificationService userIdentificationService) {
        this.wxMaService = wxMaService;
        this.userService = userService;
        this.userIdentificationService = userIdentificationService;
    }

    /**
     * Process WeChat login
     *
     * @param loginCode  The authorization code from WeChat
     * @param mobileCode The mobile authorization code from WeChat
     * @return The authenticated user
     */
    @Transactional
    public CustomUserDetails processWeChatLogin(String loginCode, String mobileCode) {
        return processWeChatLogin(loginCode, mobileCode, null);
    }

    /**
     * Process WeChat login with referrer support
     *
     * @param loginCode  The authorization code from WeChat
     * @param mobileCode The mobile authorization code from WeChat
     * @param referrerId The referrer ID for promotion scenarios
     * @return The authenticated user
     */
    @Transactional
    public CustomUserDetails processWeChatLogin(String loginCode, String mobileCode, String referrerId) {
        try {
            // Get session info from WeChat
            WxMaJscode2SessionResult sessionResult = getWeChatSessionInfo(loginCode);
            String mobileNumber = getMobileNumber(mobileCode);

            // Extract OpenID and UnionID
            String openId = validateAndExtractOpenId(sessionResult);
            String unionId = sessionResult.getUnionid();

            logger.debug("Processing WeChat login: OpenID={}, UnionID={}, mobileNumber={}, referrerId={}", 
                        openId, unionId, mobileNumber, referrerId);

            // Find or create user
            String username = findOrCreateUser(openId, unionId, mobileNumber, referrerId);

            return userService.getUserDetails(username);
        } catch (Exception e) {
            logger.error("WeChat authentication error", e);
            throw new AuthenticationException(ERROR_AUTHENTICATION + e.getMessage());
        }
    }

    /**
     * Get WeChat session info from login code
     */
    private WxMaJscode2SessionResult getWeChatSessionInfo(String loginCode) {
        try {
            return wxMaService.jsCode2SessionInfo(loginCode);
        } catch (WxErrorException e) {
            throw new AuthenticationException(ERROR_SESSION_INFO + e.getMessage(), e);
        }
    }

    /**
     * Get mobile number from mobile code
     */
    private String getMobileNumber(String mobileCode) {
        if (mobileCode == null || mobileCode.isEmpty()) {
            return null;
        }

        try {
            WxMaPhoneNumberInfo phoneInfo = wxMaService.getUserService().getPhoneNumber(mobileCode);
            return phoneInfo.getPhoneNumber();
        } catch (WxErrorException e) {
            throw new AuthenticationException(ERROR_MOBILE_INFO + e.getMessage(), e);
        }
    }

    /**
     * Validate and extract OpenID from session result
     */
    private String validateAndExtractOpenId(WxMaJscode2SessionResult sessionResult) {
        String openId = sessionResult.getOpenid();
        if (openId == null || openId.isEmpty()) {
            throw new AuthenticationException(ERROR_OPENID_EMPTY);
        }
        return openId;
    }

    /**
     * Find existing user or create new user
     */
    private String findOrCreateUser(String openId, String unionId, String mobileNumber, String referrerId) {
        OffsetDateTime now = OffsetDateTime.now();

        // 1. Try to find user by UnionID first
        String username = findUserByUnionId(unionId, openId, now);

        // 2. If not found, try to find by OpenID
        if (username == null) {
            username = findUserByOpenId(openId);
        }

        // 3. If still not found and mobile number is available, check for existing MOBILE_NUMBER_TYPE user
        if (username == null && mobileNumber != null && !mobileNumber.isEmpty()) {
            Optional<String> mobileUsername = userIdentificationService.findUsernameByIdentifier("MOBILE_NUMBER", mobileNumber);
            if (mobileUsername.isPresent()) {
                username = mobileUsername.get();
                logger.info("Found existing user with MOBILE_NUMBER_TYPE: {}, binding WeChat identifications", username);
            }
        }

        // 4. If still not found, create new user
        if (username == null) {
            username = createNewWeChatUser(unionId, openId, mobileNumber, referrerId, now);
        }

        // 5. Ensure all WeChat identifications are present for the found/created user
        if (username != null && mobileNumber != null && !mobileNumber.isEmpty()) {
            ensureAllWeChatIdentifications(username, openId, unionId, mobileNumber, now);
        }

        return username;
    }

    /**
     * Ensure all WeChat identifications are present for the user
     * This is called when user is found by existing WeChat identifications but might be missing some
     */
    private void ensureAllWeChatIdentifications(String username, String openId, String unionId, String mobileNumber, OffsetDateTime now) {
        logger.debug("Ensuring all WeChat identifications for user: username={}, openId={}, unionId={}, mobileNumber={}", 
                   username, openId, unionId, mobileNumber);
        
        List<UserIdentificationDto> existingIdentifications = userIdentificationService.getUserIdentifications(username);
        logger.debug("Existing identifications count: {}", existingIdentifications.size());
        
        for (UserIdentificationDto id : existingIdentifications) {
            logger.debug("Existing identification: type={}, identifier={}, verified={}", 
                        id.getUserIdentificationTypeId(), id.getIdentifier(), id.getVerified());
        }
        
        // Check and add WECHAT_OPENID_TYPE identification if not exists
        boolean hasOpenId = existingIdentifications.stream()
            .anyMatch(id -> WECHAT_OPENID_TYPE.equals(id.getUserIdentificationTypeId()));
        logger.debug("Has WECHAT_OPENID_TYPE: {}", hasOpenId);
        if (!hasOpenId) {
            userIdentificationService.addUserIdentification(username, WECHAT_OPENID_TYPE, openId, true, now);
            logger.debug("Added missing WECHAT_OPENID_TYPE identification for user: {}", username);
        }
        
        // Check and add WECHAT_UNIONID_TYPE identification if not exists and unionId is available
        if (unionId != null && !unionId.isEmpty()) {
            boolean hasUnionId = existingIdentifications.stream()
                .anyMatch(id -> WECHAT_UNIONID_TYPE.equals(id.getUserIdentificationTypeId()));
            logger.debug("Has WECHAT_UNIONID_TYPE: {}", hasUnionId);
            if (!hasUnionId) {
                userIdentificationService.addUserIdentification(username, WECHAT_UNIONID_TYPE, unionId, true, now);
                logger.debug("Added missing WECHAT_UNIONID_TYPE identification for user: {}", username);
            }
        }
        
        // Check and add WECHAT_MOBILE_TYPE identification if not exists
        boolean hasWeChatMobile = existingIdentifications.stream()
            .anyMatch(id -> WECHAT_MOBILE_TYPE.equals(id.getUserIdentificationTypeId()));
        logger.debug("Has WECHAT_MOBILE_TYPE: {}, mobileNumber: {}", hasWeChatMobile, mobileNumber);
        if (!hasWeChatMobile) {
            logger.debug("Adding WECHAT_MOBILE_TYPE identification for user: {}, mobileNumber: {}", username, mobileNumber);
            userIdentificationService.addUserIdentification(username, WECHAT_MOBILE_TYPE, mobileNumber, true, now);
            logger.debug("Successfully added WECHAT_MOBILE_TYPE identification for user: {}", username);
            
            // 🔑 重要：同时更新users表中的mobile_number字段，确保getUserDetails()能正确获取手机号
            ensureUserMobileNumberUpdated(username, mobileNumber);
        } else {
            logger.debug("WECHAT_MOBILE_TYPE identification already exists for user: {}", username);
            // 🔑 即使标识已存在，也要确保users表中的mobile_number字段正确设置
            ensureUserMobileNumberUpdated(username, mobileNumber);
        }
    }

    /**
     * 确保users表中的mobile_number字段正确设置
     * 这解决了已有用户首次授权手机号时，标识表有记录但users表mobile_number字段为空的问题
     */
    private void ensureUserMobileNumberUpdated(String username, String mobileNumber) {
        if (mobileNumber == null || mobileNumber.trim().isEmpty()) {
            return;
        }
        
        try {
            // 检查当前users表中的mobile_number字段
            String currentMobileNumber = userService.getCurrentMobileNumber(username);
            
            if (currentMobileNumber == null || currentMobileNumber.trim().isEmpty()) {
                // 如果users表中的手机号为空，更新它
                userService.updateUserMobileNumber(username, mobileNumber);
                logger.info("Updated mobile_number in users table for user: {}, mobileNumber: {}", 
                           username, mobileNumber.substring(0, 3) + "****");
            } else if (!mobileNumber.equals(currentMobileNumber)) {
                // 如果手机号不一致，更新为最新的
                userService.updateUserMobileNumber(username, mobileNumber);
                logger.info("Updated mobile_number in users table for user: {} from {} to {}", 
                           username, currentMobileNumber.substring(0, 3) + "****", mobileNumber.substring(0, 3) + "****");
            } else {
                logger.debug("Mobile number in users table is already correct for user: {}", username);
            }
        } catch (Exception e) {
            logger.error("Failed to update mobile_number in users table for user: {}", username, e);
            // 不抛出异常，避免影响主要的登录流程
        }
    }

    /**
     * Find user by UnionID and handle OpenID conflicts
     */
    private String findUserByUnionId(String unionId, String openId, OffsetDateTime now) {
        if (unionId == null || unionId.isEmpty()) {
            return null;
        }

        Optional<String> usernameByUnionId = userIdentificationService.findUsernameByIdentifier(WECHAT_UNIONID_TYPE, unionId);
        if (!usernameByUnionId.isPresent()) {
            return null;
        }

        String username = usernameByUnionId.get();
        logger.debug("Found user by UnionID={}, username={}", unionId, username);

        // Handle OpenID conflicts
        handleOpenIdConflicts(username, openId, unionId, now);

        return username;
    }

    /**
     * Handle OpenID conflicts for existing users
     */
    private void handleOpenIdConflicts(String username, String openId, String unionId, OffsetDateTime now) {
        List<UserIdentificationDto> userIdentifications = userIdentificationService.getUserIdentifications(username);

        List<String> conflictingOpenIds = new ArrayList<>();
        boolean hasCurrentOpenId = false;

        for (UserIdentificationDto identification : userIdentifications) {
            if (WECHAT_OPENID_TYPE.equals(identification.getUserIdentificationTypeId())) {
                if (openId.equals(identification.getIdentifier())) {
                    hasCurrentOpenId = true;
                } else {
                    conflictingOpenIds.add(identification.getIdentifier());
                }
            }
        }

        if (!conflictingOpenIds.isEmpty()) {
            logger.warn("OpenID conflict detected for user [{}]: current={}, existing={}, unionId={}",
                    username, openId, String.join(", ", conflictingOpenIds), unionId);
        }

        // Add current OpenID if not already associated
        if (!hasCurrentOpenId && conflictingOpenIds.isEmpty()) {
            userIdentificationService.addUserIdentification(username, WECHAT_OPENID_TYPE, openId, true, now);
            logger.debug("Added OpenID to existing user: username={}, OpenID={}", username, openId);
        }
    }

    /**
     * Find user by OpenID
     */
    private String findUserByOpenId(String openId) {
        Optional<String> usernameByOpenId = userIdentificationService.findUsernameByIdentifier(WECHAT_OPENID_TYPE, openId);
        if (usernameByOpenId.isPresent()) {
            String username = usernameByOpenId.get();
            logger.debug("Found user by OpenID={}, username={}", openId, username);
            return username;
        }
        return null;
    }

    /**
     * Create a new user from WeChat authentication
     *
     * @param unionId      The union ID from WeChat
     * @param openId       The OpenID from WeChat
     * @param mobileNumber The mobile number from WeChat
     * @param referrerId   The referrer ID for promotion scenarios
     * @param now          Current timestamp
     * @return The username
     */
    private String createNewWeChatUser(String unionId, String openId, String mobileNumber, String referrerId, OffsetDateTime now) {
        // Generate username with preference for readable format (MV_ + mobile number)
        String username = generateReadableUsername(mobileNumber);
        String password = UUID.randomUUID().toString();

        logger.info("Creating new WeChat user: username={}, OpenID={}, UnionID={}, mobileNumber={}, referrerId={}", 
                   username, openId, unionId, mobileNumber, referrerId);

        // Create the user
        UserDto userDto = new UserDto();
        userDto.setUsername(username);
        userDto.setMobileNumber(mobileNumber);
        userDto.setEnabled(true);

        // Create the user in the database with referrer support
        userService.createUser(userDto, password, referrerId);

        // Link the WeChat OpenID to the user
        userIdentificationService.addUserIdentification(username, WECHAT_OPENID_TYPE, openId, true, now);

        // Also store the UnionID if available
        if (unionId != null && !unionId.isEmpty()) {
            userIdentificationService.addUserIdentification(username, WECHAT_UNIONID_TYPE, unionId, true, now);
        }

        // Store the mobile number if available
        if (mobileNumber != null && !mobileNumber.isEmpty()) {
            Optional<String> existingUser = userIdentificationService.findUsernameByIdentifier(WECHAT_MOBILE_TYPE, mobileNumber);
            if (existingUser.isEmpty()) {
                userIdentificationService.addUserIdentification(username, WECHAT_MOBILE_TYPE, mobileNumber, true, now);
            }
        }

        return username;
    }

    /**
     * Generate readable username using MV_ prefix + mobile number if available
     * Falls back to wx_ + random string for users without mobile number
     */
    private String generateReadableUsername(String mobileNumber) {
        // If mobile number is available, use MV_ prefix for consistency
        if (mobileNumber != null && !mobileNumber.isEmpty()) {
            String preferredUsername = MV_PREFIX + mobileNumber;
            
            // Check if preferred username is available
            if (!userService.userExists(preferredUsername)) {
                return preferredUsername;
            }
            
            // Fallback to random username if preferred one is taken
            String randomUsername = MV_PREFIX + UUID.randomUUID().toString().replace("-", "").substring(0, 20);
            logger.warn("Preferred username {} already exists, using random username: {}", preferredUsername, randomUsername);
            return randomUsername;
        } else {
            // For users without mobile number, use wx_ prefix
            return USERNAME_PREFIX + UUID.randomUUID().toString().replace("-", "").substring(0, USERNAME_SUFFIX_LENGTH);
        }
    }

} 