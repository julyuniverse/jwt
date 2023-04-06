package com.example.jwt.config.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
@AllArgsConstructor
@Getter
public enum ErrorCode {
    FAILED(UNAUTHORIZED, "Failed."),
    DUPLICATE_ID(UNAUTHORIZED, "Duplicate ID."),
    WRONG_PASSWORD(UNAUTHORIZED, "Wrong password."),
    ACCOUNT_NOT_FOUND(UNAUTHORIZED, "Account not found."),
    INVALID_JWT_SIGNATURE(UNAUTHORIZED, "Invalid JWT signature."),
    EXPIRED_JWT(UNAUTHORIZED, "Expired JWT."),
    UNSUPPORTED_JWT(UNAUTHORIZED, "Unsupported JWT."),
    INVALID_JWT(UNAUTHORIZED, "Invalid JWT."),
    JWT_WITHOUT_AUTHORITY_INFO(UNAUTHORIZED, "JWT without authority information."),
    UNMATCHED_JWT(UNAUTHORIZED, "Unmatched JWT."),
    LOGGED_OUT_ACCOUNT(UNAUTHORIZED, "Logged out account."),
    ;

    private final HttpStatus httpStatus;
    private final String message;
}
