package org.dddml.ffvtraceability.auth.jackson;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import java.time.OffsetDateTime;
import java.util.List;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class CustomUserDetailsMixin {

    @JsonProperty("groups")
    @JsonDeserialize(as = List.class)
    private List<String> groups;

    @JsonProperty("phoneNumber")
    private String phoneNumber;

    @JsonProperty("passwordChangeRequired")
    private boolean passwordChangeRequired;

    @JsonProperty("passwordLastChanged")
    private OffsetDateTime passwordLastChanged;

    @JsonProperty("firstLogin")
    private boolean firstLogin;
}