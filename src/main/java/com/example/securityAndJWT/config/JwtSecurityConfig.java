package com.example.securityAndJWT.config;

import com.example.securityAndJWT.security.JwtFilter;
import com.example.securityAndJWT.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 직접 만든 JwtTokenProvider와 JwtFilter를 SecurityConfig에 적용할 때 사용
@RequiredArgsConstructor
public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final JwtTokenProvider jwtTokenProvider;

    // JwtTokenProvider를 주입받아서 JwtFilter를 통해 Security 로직에 필터를 등록한다.
    // JwtFilter가 SecurityFilter보다 먼저 동작한다.(SecurityFilter 앞에 추가함)
    @Override
    public void configure(HttpSecurity http) throws Exception {
        JwtFilter customFilter = new JwtFilter(jwtTokenProvider);
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
