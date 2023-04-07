package com.example.jwt.config.jwt;

import com.example.jwt.config.exception.CustomException;
import com.example.jwt.config.exception.ErrorCode;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
@Slf4j
@Component
public class JwtProvider {
    private static final String AUTHORITIES_KEY = "auth";
    @Value("${jwt.ttl.access-token}")
    private Long accessTokenTtl;

    @Value("${jwt.ttl.refresh-token}")
    private Long refreshTokenTtl;
    private static Key key = null;

    public JwtProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        key = Keys.hmacShaKeyFor(keyBytes);
    }

    public String createAccessToken(Authentication authentication) {
        return createToken(authentication, accessTokenTtl);
    }

    public String createRefreshToken(Authentication authentication) {
        return createToken(authentication, refreshTokenTtl);
    }

    private String createToken(Authentication authentication, long ttl) {
        // 권한 가져오기
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();

        return Jwts.builder()
                .setSubject(authentication.getName())       // payload "sub": "email"
                .claim(AUTHORITIES_KEY, authorities)        // payload "auth": "ROLE_USER" (ex)
                .setExpiration(new Date(now + ttl))         // payload "exp": 1516239022 (ex)
                .signWith(key, SignatureAlgorithm.HS512)    // header "alg": "HS512"
                .compact();
    }

    public boolean validateToken(String token) {
//        try {
//            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
//
//            return true;
//        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
//            log.info("잘못된 JWT 서명이에요.");
////            throw new CustomException(ErrorCode.INVALID_JWT_SIGNATURE);
//        } catch (ExpiredJwtException e) {
//            log.info("ddd만료된 JWT에요.");
////            throw new CustomException(ErrorCode.EXPIRED_JWT);
//        } catch (UnsupportedJwtException e) {
//            log.info("지원되지 않는 JWT에요.");
////            throw new CustomException(ErrorCode.UNSUPPORTED_JWT);
//        } catch (IllegalArgumentException e) {
//            log.info("잘못된 JWT에요.");
////            throw new CustomException(ErrorCode.INVALID_JWT);
//        }
//
//        return false;

        Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);

        return true;
    }

    public Authentication getAuthentication(String accessToken) {
        // 토큰 복호화
        Claims claims = parseClaims(accessToken);

        if (claims.get(AUTHORITIES_KEY) == null) {
            throw new CustomException(ErrorCode.JWT_WITHOUT_AUTHORITY_INFO);
        }

        // 클래임에서 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // UserDetails 객체를 만들어서 Authentication 리턴
        UserDetails principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }
}
