# CLAUDE.md - WeSpringAuthServer

## Project Overview

**Type:** Spring Boot OAuth2 Authorization Server (Authentication & Authorization Service)
**Language:** Java 17
**Framework:** Spring Boot 3.4.6
**Build System:** Maven (with Maven Wrapper - mvnw)
**Authorization Server:** Spring Authorization Server 1.3.6
**Security:** Spring Security 6.2.0
**Main Port:** 9000

## Project Purpose

A standalone OAuth2 authorization server providing centralized authentication and authorization services for the FFV Traceability System. Supports multiple authentication methods:
- Username/Password
- SMS Verification Code
- WeChat Mini-Program Login

---

## Architecture

### Multi-Chain Security Filter Pattern
```
mobileApiSecurityFilterChain (/sms/**, /wechat/**)    → STATELESS, permitAll
webApiSecurityFilterChain (/api/**, /auth-srv/**)     → BASIC auth, ADMIN only
defaultSecurityFilterChain (all others)                → Form login + SMS + WeChat
```

### Authentication Flows
- Authorization Code flow with PKCE
- Refresh tokens (stored in cookies or backend)
- OIDC support for OpenID Connect

---

## Key Dependencies

| Dependency | Purpose |
|------------|---------|
| spring-security-oauth2-authorization-server | OAuth2 server implementation |
| spring-boot-starter-jdbc | Direct JDBC access (no JPA/MyBatis) |
| spring-session-jdbc | Session storage in PostgreSQL |
| postgresql | Database driver |
| spring-boot-starter-thymeleaf | Server-side HTML templating |
| weixin-java-miniapp 4.7.0 | WeChat SDK |
| dysmsapi20170525 | Aliyun SMS |
| volc-sdk-java 1.0.222 | Volcengine SMS |

---

## Directory Structure

```
src/main/java/org/dddml/ffvtraceability/auth/
├── AuthServerApplication.java          # Main entry point
├── authentication/                     # Custom auth providers (SMS, WeChat, UsernamePassword)
├── config/                             # 25+ Spring config classes
├── controller/                         # 27 REST/Web controllers
├── service/                            # Business services + SMS providers
├── security/                          # CustomUserDetails, handlers
├── dto/                               # Data transfer objects
├── mapper/                            # Database mappers
├── exception/                         # Exception handling
├── jackson/                          # JSON serialization
└── util/                              # Utility classes

src/main/resources/
├── application.yml                    # Base configuration
├── application-dev.yml                # Development profile
├── application-prod.yml              # Production profile
├── schema.sql                         # PostgreSQL schema
├── data-*.sql                        # Initial data files
├── keys/jwt-signing-keys.jks         # JWT signing keystore
└── templates/                         # Thymeleaf templates
```

---

## Key Configuration Files

| File | Purpose |
|------|---------|
| `application.yml` | Base config - server, datasource, OAuth2, JWT, logging |
| `application-dev.yml` | Dev profile - debug logging, test credentials, local CORS |
| `application-prod.yml` | Prod profile - env vars for secrets |
| `.env` / `.env.prod` | Environment variables for sensitive data |
| `schema.sql` | Database schema (users, authorities, groups, oauth2_authorization) |

---

## Key Source Modules

### authentication/
- `SmsAuthenticationFilter/Provider/Token` - SMS/cellphone verification login
- `WechatAuthenticationFilter/Provider/Token` - WeChat mini-program login
- `UsernamePasswordAuthenticationProvider` - Traditional username/password auth
- `AuthenticationUtils` - Authentication utility methods

### config/
- `AuthorizationServerConfig` - OAuth2 setup with JWT, JWKS
- `SecurityConfig` - Multi-chain security filter configuration
- `CookieSecurityConfig` - HttpOnly cookie configuration
- `OAuth2ClientSecurityConfig` - OAuth2 client settings
- `JwtKeyProperties` - JWT keystore configuration
- `AuthServerProperties` - Authorization server settings
- `SmsProviderConfig` - SMS provider configuration

### controller/
- `UserManagementApiController` - User CRUD operations
- `GroupManagementApiController` - Group/role management
- `AuthorityManagementApiController` - Hierarchical permission management
- `SmsLoginController` - SMS login API endpoints
- `SocialLoginController` - Social login (WeChat) endpoints

### service/
- `UserService` - User management, password reset, email sending
- `WeChatService` - WeChat API integration
- `OAuth2AuthenticationHelper` - OAuth2 token generation helpers
- `DatabaseSmsVerificationService` - SMS code storage/verification
- `sms/AliyunSmsProvider` - Aliyun SMS implementation
- `sms/HuoshanSmsProvider` - Volcengine SMS implementation
- `sms/SimulatorSmsProvider` - Development SMS simulator

### security/
- `CustomUserDetails` - Extended user details with phone, groups, password status

---

## Database Design

**Database:** PostgreSQL

### Key Tables
- `users`, `authorities`, `groups`, `group_members`, `group_authorities` - Spring Security standard schema
- `authority_definitions` - Hierarchical permission catalog
- `user_identifications` - Multiple login identifier support
- `oauth2_authorization` - OAuth2 tokens and grants
- `sms_verification_codes` - Phone verification storage

---

## Security Features

- **JWT Custom Claims** - Adds `phone_number`, `authorities`, `groups` to tokens
- **PKCE Support** - Proof Key for Code Exchange
- **HttpOnly Cookies** - Secure cookie configuration
- **CORS Configuration** - Flexible cross-origin setup
- **CSRF Protection** - Configurable per-endpoint
- **Hierarchical Permissions** - Tree-structured authority definitions
- **Session Storage in PostgreSQL** - Cluster support via Spring Session JDBC

---

## JWT Configuration

- Uses RSA key pair from JKS keystore (`keys/jwt-signing-keys.jks`)
- Custom claims: phone_number, authorities, groups
- Reloads user details on token refresh to get latest phone number

---

## Development Commands

```bash
# Build
./mvnw clean package

# Run development
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev

# Run production
java -jar target/*.jar --spring.profiles.active=prod

# Docker
docker build -t auth-server .
docker run -p 9000:9000 --env-file .env.prod auth-server
```

---

## Notes

- Main class: `org.dddml.ffvtraceability.auth.AuthServerApplication`
- Server runs on port **9000**
- Uses JDBCTemplate for direct JDBC access (no JPA/MyBatis)
- Has a sample resource server in `example-resource-server/` for testing
- Reference submodule at `reference-submodules/spring-authorization-server/`
