package com.apollostore.security.auth;

import com.apollostore.security.config.JwtService;
import com.apollostore.security.payload.request.AuthenticationRequest;
import com.apollostore.security.payload.request.RegisterRequest;
import com.apollostore.security.payload.response.AuthenticationResponse;
import com.apollostore.security.payload.response.ConnValidationResponse;
import com.apollostore.security.token.Token;
import com.apollostore.security.token.TokenRepository;
import com.apollostore.security.token.TokenType;
import com.apollostore.security.user.User;
import com.apollostore.security.user.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.*;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
  private final UserRepository repository;
  private final TokenRepository tokenRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  public AuthenticationResponse register(RegisterRequest request) {
    var user = User.builder()
        .firstname(request.getFirstname())
        .lastname(request.getLastname())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword()))
        .role(request.getRole())
        .build();
    var savedUser = repository.save(user);
    Map<String, Object> extraClaims = new HashMap<>();
    extraClaims.put("role", user.getRole());
    extraClaims.put("authorities", user.getRole().getPermissions());
    var jwtToken = jwtService.generateToken(extraClaims,user);
    System.out.println(jwtToken);
    var refreshToken = jwtService.generateRefreshToken(user);
    saveUserToken(savedUser, jwtToken);
    return AuthenticationResponse.builder()
        .accessToken(jwtToken)
            .refreshToken(refreshToken)
        .build();
  }

  public AuthenticationResponse authenticate(AuthenticationRequest request) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.getEmail(),
            request.getPassword()
        )
    );
    var user = repository.findByEmail(request.getEmail())
        .orElseThrow();
    var jwtToken = jwtService.generateToken(user);
    var refreshToken = jwtService.generateRefreshToken(user);
    revokeAllUserTokens(user);
    saveUserToken(user, jwtToken);
    return AuthenticationResponse.builder()
        .accessToken(jwtToken)
            .refreshToken(refreshToken)
        .build();
  }

  private void saveUserToken(User user, String jwtToken) {
    var token = Token.builder()
        .user(user)
        .token(jwtToken)
        .tokenType(TokenType.BEARER)
        .expired(false)
        .revoked(false)
        .build();
    tokenRepository.save(token);
  }

  private void revokeAllUserTokens(User user) {
    var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
    if (validUserTokens.isEmpty())
      return;
    validUserTokens.forEach(token -> {
      token.setExpired(true);
      token.setRevoked(true);
    });
    tokenRepository.saveAll(validUserTokens);
  }

  public void refreshToken(
          HttpServletRequest request,
          HttpServletResponse response
  ) throws IOException {
    final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    final String refreshToken;
    final String userEmail;
    if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
      return;
    }
    refreshToken = authHeader.substring(7);
    userEmail = jwtService.extractUsername(refreshToken);
    if (userEmail != null) {
      var user = this.repository.findByEmail(userEmail)
              .orElseThrow();
      if (jwtService.isTokenValid(refreshToken, user)) {
        var accessToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, accessToken);
        var authResponse = AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
        new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
      }
    }
  }

  public ConnValidationResponse validateToken(String tokenToValidate) {
    Optional<Token> potentialToken = tokenRepository.findByToken(tokenToValidate.replace("Bearer ", ""));

    System.out.println("IS TOKEN HERE?!?! " + tokenToValidate);
    System.out.println("POTENTIAL TOKEN PRESENT? " + potentialToken.isPresent());

//    boolean isValidToken = potentialToken
//            .map(t -> !t.isExpired() && !t.isRevoked())
//            .orElse(false);

    boolean isValidToken = potentialToken.isPresent() && !potentialToken.get().expired && !potentialToken.get().isRevoked();

    if (isValidToken) {
      User user = potentialToken.get().user;

      return ConnValidationResponse.builder()
              .status(null)
              .isAuthenticated(true)
              .username(user.getUsername())
              .token(tokenToValidate)
              .role(user.getRole())
              .authorities(user.getRole().getAuthorities())
              .build();
    } else {
      throw new RuntimeException("TOKEN INVALID");
    }

  }
}
