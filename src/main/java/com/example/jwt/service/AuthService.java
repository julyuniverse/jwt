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
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtProvider jwtProvider;
    private final RedisTemplate<String, String> redisTemplate;

    @Value("${project.name}")
    private String projectName;

    @Value("${jwt.ttl.refresh-token}")
    private Long refreshTokenTtl;

    @Transactional
    public void signup(SignupRequest signupRequest) {
        if (accountRepository.existsByEmail(signupRequest.getEmail())) {
            throw new CustomException(ErrorCode.DUPLICATE_ID); // 아이디 중복
        }

        accountRepository.save(Account.builder()
                .email(signupRequest.getEmail())
                .password(passwordEncoder.encode(signupRequest.getPassword()))
                .authority(Authority.ROLE_USER)
                .build()
        );
    }

    @Transactional
    public LoginResponse login(LoginRequest loginRequest) {
        Account account = accountRepository.findByEmail(loginRequest.getEmail())
                .orElseThrow(() -> new CustomException(ErrorCode.ACCOUNT_NOT_FOUND));
        checkPassword(loginRequest.getPassword(), account.getPassword());

        // Access token, Refresh token 생성
        // 1. ID(email), password 기반 AuthenticationToken 생성
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword());

        // 2. 사용자 검증
        // authenticate 메서드가 실행될 때 CustomUserDetailsService에서 만들었던 loadUserByUsername 메서드가 실행됨 -> 사전에 위에서 설정한 UsernamePasswordAuthenticationToken가 반드시 적용되어 있어야 한다.
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        String accessToken = jwtProvider.createAccessToken(authentication);
        String refreshToken = jwtProvider.createRefreshToken(authentication);
        Token token = new Token(accessToken, refreshToken);

        // 4. redis에 Refresh token 생성
        redisTemplate.opsForValue().set(
                projectName + ":" + account.getEmail(),
                token.getRefreshToken(),
                refreshTokenTtl,
                TimeUnit.MILLISECONDS
        );

        // 5. account 셋팅
        com.example.jwt.dto.account.Account accountResponse = setAccountResponse(account);

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

    public Token reissueToken(TokenRequest tokenRequest) {
        // 1. Refresh Token 검증
        try {
            jwtProvider.validateToken(tokenRequest.getRefreshToken());
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명이에요.");
            throw new CustomException(ErrorCode.INVALID_JWT_SIGNATURE);
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT에요.");
            throw new CustomException(ErrorCode.EXPIRED_JWT);
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT에요.");
            throw new CustomException(ErrorCode.UNSUPPORTED_JWT);
        } catch (IllegalArgumentException e) {
            log.info("잘못된 JWT에요.");
            throw new CustomException(ErrorCode.INVALID_JWT);
        }

        // 2. Access token에서 ID(email) 가져오기
        Authentication authentication = jwtProvider.getAuthentication(tokenRequest.getAccessToken());

        // 3. redis에서 email 기반으로 Refresh token 값 가져오기
        String refreshToken = redisTemplate.opsForValue().get(projectName + ":" + authentication.getName());

        // 4. Refresh token 존재 여부 체크
        if (refreshToken == null) {
            throw new CustomException(ErrorCode.LOGGED_OUT_ACCOUNT);
        }

        // 5. Refresh token 매칭 체크
        if (!Objects.equals(refreshToken, tokenRequest.getRefreshToken())) {
            throw new CustomException(ErrorCode.UNMATCHED_JWT);
        }

        // 6. 새로운 토큰 생성
        String newAccessToken = jwtProvider.createAccessToken(authentication);
        String newRefreshToken = jwtProvider.createRefreshToken(authentication);
        Token token = new Token(newAccessToken, newRefreshToken);

        // 7. redis에 Refresh token 업데이트
        redisTemplate.opsForValue().set(
                projectName + ":" + authentication.getName(),
                token.getRefreshToken(),
                refreshTokenTtl,
                TimeUnit.MILLISECONDS
        );

        return token;
    }

    private com.example.jwt.dto.account.Account setAccountResponse(Account account) {
        return com.example.jwt.dto.account.Account.builder()
                .accountId(account.getAccountId())
                .email(account.getEmail())
                .role(String.valueOf(account.getAuthority()))
                .build();
    }
}
