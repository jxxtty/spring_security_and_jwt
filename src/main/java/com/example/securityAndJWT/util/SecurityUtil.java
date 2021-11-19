package com.example.securityAndJWT.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Slf4j
public class SecurityUtil {

    // SecurityContext에 유저 정보가 저장되는 시점
    // Request가 들어올 때 JwtFilter의 doFilter에서 저장된다.
    // (API 요청이 들어오면 필터에서 Access Token을 복호화해서 유저정보를 꺼내 SecurityContext 라는 곳에 저장한다)
    public static Long getCurrentMemberId(){
        // SecurityContext에 저장된 유저정보는 전역으로, 어디서든 꺼낼 수 있다.
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || authentication.getName() == null) {
            throw new RuntimeException("Security Context에 인증정보 없음");
        }

        return Long.parseLong(authentication.getName());
    }
}
