package org.dddml.ffvtraceability.auth.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class GroupVo {
    private String groupName;
    private String description;
    /**
     * 组拥有的权限列表
     * 存储来自 authority_definitions 表的 authority_id
     * 与 Spring Security 的 authorities 概念保持一致
     */
    private List<String> authorities;

    public List<String> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<String> authorities) {
        this.authorities = authorities;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getGroupName() {
        return groupName;
    }

    public void setGroupName(String groupName) {
        this.groupName = groupName;
    }
}
