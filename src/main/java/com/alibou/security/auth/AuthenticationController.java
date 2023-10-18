package com.alibou.security.auth;

import com.alibou.security.payload.request.AuthenticationRequest;
import com.alibou.security.payload.request.RegisterRequest;
import com.alibou.security.payload.response.AuthenticationResponse;
import com.alibou.security.payload.response.ConnValidationResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

  private final AuthenticationService service;

  @PostMapping("/register")
  public ResponseEntity<AuthenticationResponse> register(
      @RequestBody RegisterRequest request
  ) {
    return ResponseEntity.ok(service.register(request));
  }
  @PostMapping("/login")
  public ResponseEntity<AuthenticationResponse> login(
      @RequestBody AuthenticationRequest request
  ) {
    return ResponseEntity.ok(service.authenticate(request));
  }

  @GetMapping("/validateToken")
  public ResponseEntity<ConnValidationResponse> validateToken(
          @RequestHeader(HttpHeaders.AUTHORIZATION) String tokenToValidate
  ) {
    return ResponseEntity.ok(service.validateToken(tokenToValidate));
  }

  @PostMapping("/refresh-token")
  public void refreshToken(
      HttpServletRequest request,
      HttpServletResponse response
  ) throws IOException {
    service.refreshToken(request, response);
  }
// For Demo Purposes
  @GetMapping("/demo-controller")
  public ResponseEntity<String> sayHello() {
    return ResponseEntity.ok("Hello from secured endpoint");
  }

}
