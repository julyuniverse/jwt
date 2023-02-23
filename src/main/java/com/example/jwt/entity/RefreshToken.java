package com.example.jwt.entity;

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
@RedisHash("refresh_token")
@AllArgsConstructor
@Builder
public class RefreshToken {
    @Id
    private Long id;

    private String refreshToken;

    @TimeToLive
    private Long expiration;

    public static RefreshToken createRefreshToken(long memberId, String refreshToken, Long remainingMilliSeconds) {
        return RefreshToken.builder()
                .id(memberId)
                .refreshToken(refreshToken)
                .expiration(remainingMilliSeconds / 1000)
                .build();
    }
}
