package com.example.jwt.contoller;

import com.example.jwt.dto.auth.LoginRequest;
import com.example.jwt.dto.auth.LoginResponse;
import com.example.jwt.dto.auth.SignupRequest;
import com.example.jwt.dto.token.Token;
import com.example.jwt.dto.token.TokenRequest;
import com.example.jwt.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@RequestBody SignupRequest signupRequest) {
        authService.signup(signupRequest);

        return ResponseEntity.status(HttpStatusCode.valueOf(201)).build();
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(authService.login(loginRequest));
    }

    @PostMapping("/token/reissue")
    public ResponseEntity<Token> reissueToken(@RequestBody TokenRequest tokenRequest) {
        return ResponseEntity.ok(authService.reissueToken(tokenRequest));
    }
}
