package com.apollostore.security.payload.response;

import com.apollostore.security.user.Role;
import lombok.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

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
}