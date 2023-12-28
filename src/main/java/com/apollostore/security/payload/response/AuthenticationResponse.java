package com.apollostore.security.payload.response;

import com.apollostore.security.user.Permission;
import com.apollostore.security.user.Role;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {

  @JsonProperty("access_token")
  private String accessToken;
  @JsonProperty("refresh_token")
  private String refreshToken;

  private Integer uuid;
  private String firstname;
  private String lastname;
  private String email;

  @Enumerated(EnumType.STRING)
  private Role role;

  private Set<Permission> permissions;


}
