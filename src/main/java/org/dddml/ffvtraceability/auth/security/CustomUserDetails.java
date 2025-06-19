package org.dddml.ffvtraceability.auth.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonIgnoreProperties(ignoreUnknown = true)
public class CustomUserDetails implements UserDetails {

    private final String username;
    private final String password;
    private final boolean enabled;
    private final boolean accountNonExpired;
    private final boolean credentialsNonExpired;
    private final boolean accountNonLocked;
    private final Collection<? extends GrantedAuthority> authorities;
    private final Map<String, Object> additionalDetails;
    
    // Additional fields
    private List<String> groups;
    private String phoneNumber;
    private boolean passwordChangeRequired;
    private OffsetDateTime passwordLastChanged;
    private boolean firstLogin;

    @JsonCreator
    public CustomUserDetails(
            @JsonProperty("username") String username,
            @JsonProperty("password") String password,
            @JsonProperty("enabled") boolean enabled,
            @JsonProperty("accountNonExpired") boolean accountNonExpired,
            @JsonProperty("credentialsNonExpired") boolean credentialsNonExpired,
            @JsonProperty("accountNonLocked") boolean accountNonLocked,
            @JsonProperty("authorities") Collection<? extends GrantedAuthority> authorities,
            @JsonProperty("additionalDetails") Map<String, Object> additionalDetails,
            @JsonProperty("groups") List<String> groups,
            @JsonProperty("phoneNumber") String phoneNumber,
            @JsonProperty("passwordChangeRequired") boolean passwordChangeRequired,
            @JsonProperty("passwordLastChanged") OffsetDateTime passwordLastChanged,
            @JsonProperty("firstLogin") boolean firstLogin) {
        this.username = username;
        this.password = password;
        this.enabled = enabled;
        this.accountNonExpired = accountNonExpired;
        this.credentialsNonExpired = credentialsNonExpired;
        this.accountNonLocked = accountNonLocked;
        this.authorities = authorities != null ? authorities : Collections.emptyList();
        this.additionalDetails = additionalDetails != null ? additionalDetails : Collections.emptyMap();
        this.groups = groups;
        this.phoneNumber = phoneNumber;
        this.passwordChangeRequired = passwordChangeRequired;
        this.passwordLastChanged = passwordLastChanged;
        this.firstLogin = firstLogin;
    }

    // Legacy constructor for compatibility
    public CustomUserDetails(String username, String password, boolean enabled, 
                           Collection<? extends GrantedAuthority> authorities, 
                           List<String> groups, boolean passwordChangeRequired, 
                           OffsetDateTime passwordLastChanged, boolean firstLogin) {
        this(username, password, enabled, true, true, true, authorities, 
             Collections.emptyMap(), groups, null, passwordChangeRequired, 
             passwordLastChanged, firstLogin);
    }

    @Override
    @JsonProperty("username")
    public String getUsername() {
        return username;
    }

    @Override
    @JsonProperty("password")
    public String getPassword() {
        return password;
    }

    @Override
    @JsonProperty("enabled")
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    @JsonProperty("accountNonExpired")
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    @JsonProperty("credentialsNonExpired")
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    @JsonProperty("accountNonLocked")
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    @JsonProperty("authorities")
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @JsonProperty("additionalDetails")
    public Map<String, Object> getAdditionalDetails() {
        return additionalDetails;
    }

    @JsonProperty("groups")
    public List<String> getGroups() {
        return groups;
    }

    public void setGroups(List<String> groups) {
        this.groups = groups;
    }

    @JsonProperty("phoneNumber")
    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    @JsonProperty("passwordChangeRequired")
    public boolean isPasswordChangeRequired() {
        return passwordChangeRequired;
    }

    @JsonProperty("passwordLastChanged")
    public OffsetDateTime getPasswordLastChanged() {
        return passwordLastChanged;
    }

    @JsonProperty("firstLogin")
    public boolean isFirstLogin() {
        return firstLogin;
    }

    @JsonProperty("passwordExpired")
    public boolean isPasswordExpired() {
        if (passwordLastChanged == null) {
            return true;
        }
        return passwordLastChanged.plusMonths(3)
                .isBefore(OffsetDateTime.now());
    }

    @Override
    public String toString() {
        return String.format("CustomUserDetails [Username=%s, Password=[PROTECTED], Enabled=%s, " +
                "AccountNonExpired=%s, CredentialsNonExpired=%s, AccountNonLocked=%s, " +
                "Granted Authorities=%s]",
                username, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }
}