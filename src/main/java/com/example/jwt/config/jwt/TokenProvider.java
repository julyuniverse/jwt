package com.example.jwt.config.jwt;

import com.example.jwt.dto.token.TokenDto;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
@Slf4j
@Component
public class TokenProvider {
    private static final String AUTHORITIES_KEY = "auth";
    private static final long ACCESS_TOKEN_VALIDITY_TIME = 1000 * 60 * 30;              // 30분
    private static final long REFRESH_TOKEN_VALIDITY_TIME = 1000 * 60 * 60 * 24 * 7;    // 7일
    private final Key key;

    public TokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public String createAccessToken(Authentication authentication) {
        return createToken(authentication, ACCESS_TOKEN_VALIDITY_TIME);
    }

    public String createRefreshToken(Authentication authentication) {
        return createToken(authentication, REFRESH_TOKEN_VALIDITY_TIME);
    }

    private String createToken(Authentication authentication, long tokenValidityTime) {
        // 권한 가져오기
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();

        return Jwts.builder()
                .setSubject(authentication.getName())               // payload "sub": "email"
                .claim(AUTHORITIES_KEY, authorities)                // payload "auth": "ROLE_USER" (ex)
                .setExpiration(new Date(now + tokenValidityTime))   // payload "exp": 1516239022 (ex)
                .signWith(key, SignatureAlgorithm.HS512)            // header "alg": "HS512"
                .compact();
    }
}
