package org.dddml.ffvtraceability.auth.service;

import cn.binarywang.wx.miniapp.api.WxMaService;
import cn.binarywang.wx.miniapp.bean.WxMaJscode2SessionResult;
import me.chanjar.weixin.common.error.WxErrorException;
import org.dddml.ffvtraceability.auth.dto.UserDto;
import org.dddml.ffvtraceability.auth.dto.UserIdentificationDto;
import org.dddml.ffvtraceability.auth.exception.AuthenticationException;
import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

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

    /**
     * Process WeChat login
     *
     * @param code The authorization code from WeChat
     * @return The authenticated user
     */
    @Transactional
    public CustomUserDetails processWeChatLogin(String code) {
        try {
            // Get access token, OpenID and UnionID (if available) from WeChat
            WxMaJscode2SessionResult jscode2SessionResult = wxMaService.jsCode2SessionInfo(code);
            String openId = jscode2SessionResult.getOpenid();
            String unionId = jscode2SessionResult.getUnionid();

            // 记录当前登录的 OpenID 和 UnionID 信息
            logger.info("Processing WeChat login: OpenID={}, UnionID={}", openId, unionId);

            // 缓存查询结果，避免重复查询数据库
            Optional<String> userByUnionId = Optional.empty();
            Optional<String> userByOpenId = Optional.empty();
            Map<String, List<UserIdentificationDto>> userIdentificationsCache = new HashMap<>();

            // 确定用户账号的逻辑
            String username = null;

            // 1. 优先使用 UnionID 查找用户
            if (unionId != null && !unionId.isEmpty()) {
                userByUnionId = userIdentificationService.findUsernameByIdentifier("WECHAT_UNIONID", unionId);

                if (userByUnionId.isPresent()) {
                    username = userByUnionId.get();
                    logger.info("Found user by UnionID: username={}", username);

                    // 获取用户所有标识并缓存
                    List<UserIdentificationDto> userIdentifications = userIdentificationService.getUserIdentifications(username);
                    userIdentificationsCache.put(username, userIdentifications);

                    // 检查该用户是否已关联其他 OpenID
                    boolean hasOpenIdConflict = false;
                    List<String> conflictingOpenIds = new ArrayList<>();

                    for (UserIdentificationDto identification : userIdentifications) {
                        if ("WECHAT_OPENID".equals(identification.getUserIdentificationTypeId()) && !openId.equals(identification.getIdentifier())) {
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
                        boolean hasOpenId = userIdentifications.stream().anyMatch(id -> "WECHAT_OPENID".equals(id.getUserIdentificationTypeId()) && openId.equals(id.getIdentifier()));

                        if (!hasOpenId) {
                            userIdentificationService.addUserIdentification(username, "WECHAT_OPENID", openId, true);
                            logger.info("Added OpenID to existing user: username={}, OpenID={}", username, openId);
                        }
                    }
                }
            }
            // 2. 如果没有找到 UnionID 对应的用户，使用 OpenID 查找
            if (username == null) {
                userByOpenId = userIdentificationService.findUsernameByIdentifier("WECHAT_OPENID", openId);

                if (userByOpenId.isPresent()) {
                    username = userByOpenId.get();
                    logger.info("Found user by OpenID: username={}", username);

                    // 检查情况：已找到OpenID的用户，且存在UnionID，但未关联到该用户
                    if (unionId != null && !unionId.isEmpty()) {
                        // 获取用户所有标识（如果未缓存）
                        List<UserIdentificationDto> userIdentifications = userIdentificationsCache.computeIfAbsent(username, userIdentificationService::getUserIdentifications);

                        boolean hasUnionId = userIdentifications.stream().anyMatch(id -> "WECHAT_UNIONID".equals(id.getUserIdentificationTypeId()));

                        if (!hasUnionId) {
                            // 不需要再次查询UnionID是否已关联其他用户，因为在步骤1已经检查过
                            // 如果UnionID关联了其他用户，那么username已经在步骤1中被设置了
                            if (!userByUnionId.isPresent()) {
                                // 添加UnionID到当前用户
                                userIdentificationService.addUserIdentification(username, "WECHAT_UNIONID", unionId, true);
                                logger.info("Added UnionID to existing user: username={}, UnionID={}", username, unionId);
                            }
                        }
                    }
                }
            }
            // 3. 处理UnionID和OpenID指向不同用户的情况
            if (unionId != null && !unionId.isEmpty() && userByUnionId.isPresent() && userByOpenId.isPresent() && !userByUnionId.get().equals(userByOpenId.get())) {
                // UnionID和OpenID指向不同用户，发出警告
                logger.warn("WeChat identity conflict! UnionID={} is associated with user={}, " + "while OpenID={} is associated with user={}", unionId, userByUnionId.get(), openId, userByOpenId.get());

                // 使用UnionID对应的用户
                username = userByUnionId.get();
                logger.info("Using UnionID user in conflict case: username={}", username);
            }
            // 4. 如果仍未找到用户，创建新用户
            if (username == null) {
                username = createNewWeChatUser(jscode2SessionResult);
            }
            return userService.getUserDetails(username);
        } catch (Exception e) {
            logger.error("WeChat authentication error", e);
            throw new AuthenticationException("Failed to authenticate with WeChat: " + e.getMessage());
        }
    }

    /**
     * Create a new user from WeChat authentication
     *
     * @param accessToken The OAuth2 access token from WeChat
     * @return The authentication token
     */
    private String createNewWeChatUser(WxMaJscode2SessionResult accessToken) throws WxErrorException {
        // Get user info from WeChat using OAuth2 user info API
        //WxOAuth2UserInfo userInfo =null;//wxMaService.getUserService().getUserInfo(); wxMpService.getOAuth2Service().getUserInfo(accessToken, null);

        // Generate a random username and password
        String username = "wx_" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        String password = UUID.randomUUID().toString();
        String openId = accessToken.getOpenid();
        String unionId = accessToken.getUnionid();

        logger.info("Creating new WeChat user: username={}, OpenID={}, UnionID={}", username, openId, unionId);

        // Create the user
        UserDto userDto = new UserDto();
        userDto.setUsername(username);
        userDto.setEnabled(true);

        // Set user profile information
        //userDto.setFirstName(userInfo.getNickname());
        // Use WeChat profile image if available
//        if (userInfo.getHeadImgUrl() != null && !userInfo.getHeadImgUrl().isEmpty()) {
//            userDto.setProfileImageUrl(userInfo.getHeadImgUrl());
//        }

        // Create the user in the database
        userService.createUser(userDto, password);

        // Link the WeChat OpenID to the user
        userIdentificationService.addUserIdentification(username, "WECHAT_OPENID", openId, true);

        // Also store the UnionID if available
        if (unionId != null && !unionId.isEmpty()) {
            userIdentificationService.addUserIdentification(username, "WECHAT_UNIONID", unionId, true);
        }

        // Authenticate the user
        return username;
    }

} 