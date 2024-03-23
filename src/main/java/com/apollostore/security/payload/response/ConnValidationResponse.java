package com.apollostore.security.payload.response;

import com.apollostore.security.user.Permission;
import com.apollostore.security.user.Role;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.Set;

@Getter
@Builder
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class ConnValidationResponse {
    private String status;
    private boolean isAuthenticated;
    private String username;
    private String token;
    private Role role;
    /* Use getAuthorities() to populate below in /validateToken controller! */
    private List<SimpleGrantedAuthority> authorities;

    @JsonProperty("access_token")
    private String accessToken;
    @JsonProperty("refresh_token")
    private String refreshToken;

    private Integer uuid;
    private String firstname;
    private String lastname;
    private String email;

    private Set<Permission> permissions;
}
