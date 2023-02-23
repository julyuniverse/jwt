package com.example.jwt.service;

import com.example.jwt.config.exception.CustomException;
import com.example.jwt.config.exception.ErrorCode;
import com.example.jwt.config.jwt.TokenProvider;
import com.example.jwt.dto.auth.LoginRequest;
import com.example.jwt.dto.auth.SignupRequest;
import com.example.jwt.dto.token.TokenDto;
import com.example.jwt.entity.Authority;
import com.example.jwt.entity.Member;
import com.example.jwt.entity.RefreshToken;
import com.example.jwt.repository.MemberRepository;
import com.example.jwt.repository.RefreshTokenRepository;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
@Service
@RequiredArgsConstructor
public class AuthService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    public void signup(SignupRequest signupRequest) {
        if (memberRepository.existsByEmail(signupRequest.getEmail())) {
            throw new CustomException(ErrorCode.DUPLICATE_ID); // 아이디 중복
        }

        Member member = new Member();
        member.setEmail(signupRequest.getEmail());
        member.setPassword(passwordEncoder.encode(signupRequest.getPassword()));
        member.setAuthority(Authority.ROLE_USER);
        memberRepository.save(member);
    }

    public TokenDto login(LoginRequest loginRequest) {
        Member member = memberRepository.findByEmail(loginRequest.getEmail()).orElseThrow(() -> new CustomException(ErrorCode.NOT_FOUND_IN_DB));
        checkPassword(loginRequest.getPassword(), member.getPassword());

        // access token, refresh token 생성
        // 1. ID(email), password 기반 AuthenticationToken 생성
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword());

        // 2. 사용자 검증
        // authenticate 메서드가 실행될 때 CustomUserDetailsService에서 만들었던 loadUserByUsername 메서드가 실행됨 -> 사전에 위에서 설정한 UsernamePasswordAuthenticationToken가 반드시 적용되어 있어야 한다.
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        String accessToken = tokenProvider.createAccessToken(authentication);
        String refreshToken = tokenProvider.createRefreshToken(authentication);
        TokenDto tokenDto = new TokenDto(accessToken, refreshToken);

        // 4. refresh token 생성
        refreshTokenRepository.save(RefreshToken.createRefreshToken(member.getEmail(), tokenDto.getRefreshToken()));

        // 5. 토큰 발급
        return tokenDto;
    }

    private void checkPassword(String rawPassword, String encodedPassword) {
        if (!passwordEncoder.matches(rawPassword, encodedPassword)) {
            throw new CustomException(ErrorCode.WRONG_PASSWORD);
        }
    }
}
