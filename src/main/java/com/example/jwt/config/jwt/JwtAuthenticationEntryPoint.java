package com.example.jwt.config.jwt;

import com.example.jwt.config.exception.ErrorCode;
import com.google.gson.JsonObject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.OffsetDateTime;

/**
 * @author Lee Taesung
 * @since 2023/02/24
 */
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        String exception = (String) request.getAttribute("exception");

        if (exception == null) {
            setResponse(response, ErrorCode.FAILED);
        } else if (exception.equals(ErrorCode.INVALID_JWT_SIGNATURE.name())) {
            setResponse(response, ErrorCode.INVALID_JWT_SIGNATURE);
        } else if (exception.equals(ErrorCode.EXPIRED_JWT.name())) {
            setResponse(response, ErrorCode.EXPIRED_JWT);
        } else if (exception.equals(ErrorCode.UNSUPPORTED_JWT.name())) {
            setResponse(response, ErrorCode.UNSUPPORTED_JWT);
        } else if (exception.equals(ErrorCode.INVALID_JWT.name())) {
            setResponse(response, ErrorCode.INVALID_JWT);
        }
    }

    // 한글 출력을 위해 getWriter() 사용
    private void setResponse(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        JsonObject responseJson = new JsonObject();
        responseJson.addProperty("timestamp", String.valueOf(OffsetDateTime.now()));
        responseJson.addProperty("status", String.valueOf(errorCode.getHttpStatus().value()));
        responseJson.addProperty("error", errorCode.getHttpStatus().name());
        responseJson.addProperty("message", errorCode.getMessage());
        responseJson.addProperty("code", errorCode.name());
        response.getWriter().print(responseJson);
    }
}
