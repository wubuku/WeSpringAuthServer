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

    private final WxMaService wxMaService;
    //private final WeChatConfig weChatConfig;
    private final UserService userService;
    private final UserIdentificationService userIdentificationService;

    public WeChatService(WxMaService wxMaService, UserService userService, UserIdentificationService userIdentificationService) {
        this.wxMaService = wxMaService;
        //this.weChatConfig = weChatConfig;
        this.userService = userService;
        this.userIdentificationService = userIdentificationService;
    }


    private String findUsernameByUnionId(String unionId, String openId) {
        return null;
    }

    /**
     * Process WeChat login
     *
     * @param loginCode The authorization code from WeChat
     * @return The authenticated user
     */
    @Transactional
    public CustomUserDetails processWeChatLogin(String loginCode, String mobileCode) {
        WxMaJscode2SessionResult jscode2SessionResult = null;
        try {
            // Get access token, OpenID and UnionID (if available) from WeChat
            jscode2SessionResult = wxMaService.jsCode2SessionInfo(loginCode);
        } catch (WxErrorException e) {
            throw new AuthenticationException("Failed to get WeChat session info:" + e.getMessage(), e);
        }
        String mobileNumber = null;
        if (mobileCode != null && !mobileCode.isEmpty()) {
            try {
                WxMaPhoneNumberInfo wxMaPhoneNumberInfo = wxMaService.getUserService().getPhoneNumber(mobileCode);
                mobileNumber = wxMaPhoneNumberInfo.getPhoneNumber();
            } catch (WxErrorException e) {
                throw new AuthenticationException("Failed to get user mobile info:" + e.getMessage(), e);
            }
        }
        try {
            String openId = jscode2SessionResult.getOpenid();
            if (openId == null || openId.isEmpty()) {
                throw new AuthenticationException("Failed to get WeChat session info: OpenID is empty");
            }
            String unionId = jscode2SessionResult.getUnionid();
            // 记录当前登录的 OpenID 和 UnionID 信息
            logger.info("Processing WeChat login: OpenID={}, UnionID={}", openId, unionId);

            // 缓存查询结果，避免重复查询数据库
            Optional<String> usernameByOpenId = Optional.empty();
            Optional<String> usernameByUnionId = Optional.empty();
            //Map<String, List<UserIdentificationDto>> userIdentificationsCache = new HashMap<>();

            // 确定用户账号的逻辑
            String username = null;
            OffsetDateTime now = OffsetDateTime.now();
            // 1. 优先使用 UnionID 查找用户
            if (unionId != null && !unionId.isEmpty()) {
                usernameByUnionId = userIdentificationService.findUsernameByIdentifier("WECHAT_UNIONID", unionId);
                if (usernameByUnionId.isPresent()) {
                    username = usernameByUnionId.get();
                    logger.info("Found user by UnionID={},username={}", unionId, username);
                    // 获取用户所有标识并缓存
                    List<UserIdentificationDto> userIdentifications = userIdentificationService.getUserIdentifications(username);
                    //userIdentificationsCache.put(username, userIdentifications);

                    // 检查该用户是否已关联其他 OpenID
                    boolean hasOpenIdConflict = false;
                    List<String> conflictingOpenIds = new ArrayList<>();

                    for (UserIdentificationDto identification : userIdentifications) {
                        if ("WECHAT_OPENID".equals(identification.getUserIdentificationTypeId())
                                && !openId.equals(identification.getIdentifier())) {
                            // 该用户已关联了不同的 OpenID
                            hasOpenIdConflict = true;
                            conflictingOpenIds.add(identification.getIdentifier());
                        }
                    }
                    if (hasOpenIdConflict) {
                        // 详细记录冲突信息
                        logger.warn("⚠️ OpenID Conflict Detected: User [{}] has other OpenIDs different from current", username);
                        logger.warn("  - Current login OpenID: {}", openId);
                        logger.warn("  - User's existing OpenIDs: {}", String.join(", ", conflictingOpenIds));
                        logger.warn("  - UnionID: {}", unionId);
                    }
                    // 如果没有关联当前OpenID，则添加
                    if (!hasOpenIdConflict) {
                        boolean hasOpenId = userIdentifications.stream().anyMatch(id ->
                                "WECHAT_OPENID".equals(id.getUserIdentificationTypeId()) && openId.equals(id.getIdentifier()));
                        if (!hasOpenId) {
                            userIdentificationService.addUserIdentification(username, "WECHAT_OPENID", openId, true, now);
                            logger.info("Added OpenID to existing user: username={}, OpenID={}", username, openId);
                        }
                    }
                }
            }
            // 2. 如果没有找到 UnionID 对应的用户，使用 OpenID 查找
            if (username == null) {
                usernameByOpenId = userIdentificationService.findUsernameByIdentifier("WECHAT_OPENID", openId);
                if (usernameByOpenId.isPresent()) { //如果使用 OpenId 找到了 username
                    username = usernameByOpenId.get();
                    logger.info("Found user by OpenID={},username={}", openId, username);
                }
            }
            // 3. 如果仍未找到用户，创建新用户
            if (username == null) {
                username = createNewWeChatUser(unionId, openId, mobileNumber, now);
            }
            //这里可能会抛出 UsernameNotFoundException 异常
            return userService.getUserDetails(username);
        } catch (Exception e) {
            logger.error("WeChat authentication error", e);
            throw new AuthenticationException("Failed to authenticate with WeChat: " + e.getMessage());
        }
    }

    /**
     * Create a new user from WeChat authentication
     *
     * @param unionId      The union ID from WeChat
     * @param openId       The OpenID from WeChat
     * @param mobileNumber The mobile number from WeChat
     * @return The authentication token
     */
    private String createNewWeChatUser(String unionId, String openId, String mobileNumber, OffsetDateTime now) {
        // Generate a random username and password
        String username = "wx_" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        String password = UUID.randomUUID().toString();

        logger.info("Creating new WeChat user: username={}, OpenID={}, UnionID={}", username, openId, unionId);

        // Create the user
        UserDto userDto = new UserDto();
        userDto.setUsername(username);
        userDto.setMobileNumber(mobileNumber);
        userDto.setEnabled(true);

        // Create the user in the database
        userService.createUser(userDto, password);
        // Link the WeChat OpenID to the user
        userIdentificationService.addUserIdentification(username, "WECHAT_OPENID", openId, true, now);
        // Also store the UnionID if available
        if (unionId != null && !unionId.isEmpty()) {
            userIdentificationService.addUserIdentification(username, "WECHAT_UNIONID", unionId, true, now);
        }
        // Store the mobile number if available
        if (mobileNumber != null && !mobileNumber.isEmpty()) {
            Optional<String> usernameByMobileNumber = userIdentificationService.findUsernameByIdentifier("MOBILE_NUMBER", openId);
            if (usernameByMobileNumber.isEmpty()) {
                userIdentificationService.addUserIdentification(username, "MOBILE_NUMBER", mobileNumber, true, now);
            }
        }
        // Authenticate the user
        return username;
    }

} 