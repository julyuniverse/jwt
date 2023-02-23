package com.example.jwt.entity;

import com.example.jwt.config.jwt.TokenProvider;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
@Getter
@RedisHash(value = "refresh_token", timeToLive = 60L)
@AllArgsConstructor
@Builder
public class RefreshToken {
    @Id
    private String id;

    private String refreshToken;

    @TimeToLive
    private Long expiration;

    public static RefreshToken createRefreshToken(String email, String refreshToken) {
        return RefreshToken.builder()
                .id(email)
                .refreshToken(refreshToken)
                .build();
    }
}
