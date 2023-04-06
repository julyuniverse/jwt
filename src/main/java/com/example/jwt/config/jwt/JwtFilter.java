package com.example.jwt.config.jwt;

import com.example.jwt.config.exception.ErrorCode;
import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * @author Lee Taesung
 * @since 2023/02/24
 */
@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";
    private final JwtProvider jwtProvider;

    // 실제 필터링 로직은 doFilterInternal에 들어감
    // JWT 토큰의 인증 정보를 현재 쓰레드의 SecurityContext에 저장하는 역할 수행
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        // 1. Request header에서 토큰을 꺼냄
        String jwt = resolveToken(request);

        try {
            // 2. validateToken으로 토큰 유효성 검사
            // 정상 토큰이면 해당 토큰으로 Authentication을 가져와서 SecurityContext에 저장
            if (StringUtils.hasText(jwt) && jwtProvider.validateToken(jwt)) {
                Authentication authentication = jwtProvider.getAuthentication(jwt);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명이에요.");
            request.setAttribute("exception", ErrorCode.INVALID_JWT_SIGNATURE.name());
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT에요.");
            request.setAttribute("exception", ErrorCode.EXPIRED_JWT.name());
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT에요.");
            request.setAttribute("exception", ErrorCode.UNSUPPORTED_JWT.name());
        } catch (IllegalArgumentException e) {
            log.info("잘못된 JWT에요.");
            request.setAttribute("exception", ErrorCode.INVALID_JWT.name());
        }

        filterChain.doFilter(request, response);
    }

    // Request header에서 토큰 정보를 꺼냄
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(7);
        }

        return null;
    }
}
