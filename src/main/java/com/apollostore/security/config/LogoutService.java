package com.apollostore.security.config;

import com.apollostore.security.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

  private final TokenRepository tokenRepository;

  @Override
  public void logout(
      HttpServletRequest request,
      HttpServletResponse response,
      Authentication authentication
  ) {
    final String jwt;
    final String authHeader = request.getHeader("Authorization");

    if (authHeader == null ||!authHeader.startsWith("Bearer ")) return;
    jwt = authHeader.substring(7);

    var storedToken = tokenRepository.findByToken(jwt)
        .orElse(null);

    if (storedToken != null) {
      System.out.println("RIGHT Spot!!");
      storedToken.setExpired(true);
      storedToken.setRevoked(true);
      tokenRepository.save(storedToken);
      SecurityContextHolder.clearContext();
    }
  }
}
