package com.example.securityAndJWT.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Request Header에서 AccessToken을 꺼내고 여러가지 검사 후 유저 정보를 꺼내서 SecurityContext에 저장
 * 가입/로그인/재발급을 제외한 모든 request는 이 필터를 거치기 때문에, 토큰 정보가 없거나 유효하기 않으면 정상적으로 수행되지 않는다.
 * 그리고 요청이 정상적으로 Controller까지 도착했다면 SecurityContext에 Member ID가 존재한다는 것이 보장된다.
 * 대신 직접 DB를 조회한 것이 아니라 Access Token에 있는 Member ID를 꺼낸것이라서, 탈퇴로 인해 Member ID가 DB에 없는 경우 등의 상황은 Service단에서 걸러줘야한다.
 */
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter { // OncePerRequestFilter 인터페이스를 구현 -> 요청 받을 때 단 한번만 실행된다.
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer";

    private final JwtTokenProvider jwtTokenProvider;

    // 실제 필터링 로직은 doFilterInternal에 들어간다
    // jwt 토큰의 인증 정보를 현재 쓰레드의 SecurityContext에 저장하는 역할을 수행한다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 1. Request Header에서 토큰을 꺼낸다.
        String jwt = resolveToken(request);

        // 2. validateToken으로 토큰 유효성을 검사한다.
        // 정상 토큰이면 해당 토큰으로 Authentication을 가져와서 SecurityContext에 저장해준다.
        if (StringUtils.hasText(jwt) && jwtTokenProvider.validateToken(jwt)) {
            Authentication authentication = jwtTokenProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);

    }

    // Request Header에서 토큰 정보를 꺼내온다.
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
