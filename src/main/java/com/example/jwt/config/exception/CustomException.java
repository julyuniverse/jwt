package com.example.jwt.config.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
@AllArgsConstructor
@Getter
public class CustomException extends RuntimeException {
    private final ErrorCode errorCode;
}
