package com.example.jwt.service;

import com.example.jwt.config.exception.CustomException;
import com.example.jwt.config.exception.ErrorCode;
import com.example.jwt.config.jwt.JwtProvider;
import com.example.jwt.dto.auth.LoginRequest;
import com.example.jwt.dto.auth.LoginResponse;
import com.example.jwt.dto.auth.SignupRequest;
import com.example.jwt.dto.token.Token;
import com.example.jwt.dto.token.TokenRequest;
import com.example.jwt.entity.Account;
import com.example.jwt.entity.Authority;
import com.example.jwt.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
@Service
@RequiredArgsConstructor
public class AuthService {
    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtProvider jwtProvider;
    private final AccountService accountService;
    private final RedisTemplate<String, String> redisTemplate;
    @Value("${jwt.ttl.refresh-token}")
    private Long refreshTokenTtl;

    @Transactional
    public void signup(SignupRequest signupRequest) {
        if (accountRepository.existsByEmail(signupRequest.getEmail())) {
            throw new CustomException(ErrorCode.DUPLICATE_ID); // 아이디 중복
        }

        Account account = new Account();
        account.setEmail(signupRequest.getEmail());
        account.setPassword(passwordEncoder.encode(signupRequest.getPassword()));
        account.setAuthority(Authority.ROLE_USER);
        accountRepository.save(account);
    }

    @Transactional
    public LoginResponse login(LoginRequest loginRequest) {
        Account account = accountService.findByEmail(loginRequest.getEmail());
        checkPassword(loginRequest.getPassword(), account.getPassword());

        // access token, refresh token 생성
        // 1. ID(email), password 기반 AuthenticationToken 생성
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword());

        // 2. 사용자 검증
        // authenticate 메서드가 실행될 때 CustomUserDetailsService에서 만들었던 loadUserByUsername 메서드가 실행됨 -> 사전에 위에서 설정한 UsernamePasswordAuthenticationToken가 반드시 적용되어 있어야 한다.
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        String accessToken = jwtProvider.createAccessToken(authentication);
        String refreshToken = jwtProvider.createRefreshToken(authentication);
        Token token = new Token(accessToken, refreshToken);

        // 4. redis에 refresh token 생성
        redisTemplate.opsForValue().set(
                account.getEmail(),
                token.getRefreshToken(),
                refreshTokenTtl,
                TimeUnit.MILLISECONDS
        );

        // 5. account 셋팅
        com.example.jwt.dto.account.Account accountResponse = accountService.setAccountResponse(account);

        return LoginResponse.builder()
                .account(accountResponse)
                .token(token)
                .build();
    }

    private void checkPassword(String rawPassword, String encodedPassword) {
        if (!passwordEncoder.matches(rawPassword, encodedPassword)) {
            throw new CustomException(ErrorCode.WRONG_PASSWORD);
        }
    }

    public Token reissue(TokenRequest tokenRequest) {
        // 1. Refresh Token 검증
        if (!jwtProvider.validateToken(tokenRequest.getRefreshToken())) {
            throw new CustomException(ErrorCode.INVALID_JWT);
        }

        // 2. Access Token에서 ID(email) 가져오기
        Authentication authentication = jwtProvider.getAuthentication(tokenRequest.getAccessToken());

        // 3. redis에서 email 기반으로 Refresh Token 값 가져오기
        String refreshToken = redisTemplate.opsForValue().get(authentication.getName());

        // 4. 유무 체크
        if (refreshToken == null) {
            throw new CustomException(ErrorCode.LOGGED_OUT_ACCOUNT);
        }

        // 매칭 체크
        if (!Objects.equals(refreshToken, tokenRequest.getRefreshToken())) {
            throw new CustomException(ErrorCode.UNMATCHED_JWT);
        }

        // 5. 새로운 토큰 생성
        String newAccessToken = jwtProvider.createAccessToken(authentication);
        String newRefreshToken = jwtProvider.createRefreshToken(authentication);
        Token token = new Token(newAccessToken, newRefreshToken);

        // 6. redis에 refresh token 업데이트
        redisTemplate.opsForValue().set(
                authentication.getName(),
                token.getRefreshToken(),
                refreshTokenTtl,
                TimeUnit.MILLISECONDS
        );

        return token;
    }
}
