package com.example.jwt.config.spring;

import lombok.Getter;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
@Getter
public class CacheKey {
    public static final String USER = "user";
    public static final int DEFAULT_EXPIRE_SEC = 60;
}
