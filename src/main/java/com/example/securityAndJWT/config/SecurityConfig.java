package com.example.securityAndJWT.config;

import com.example.securityAndJWT.security.JwtAccessDeniedHandler;
import com.example.securityAndJWT.security.JwtAuthenticationEntryPoint;
import com.example.securityAndJWT.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

// Spring Security의 가장 기본적인 설정, JWT를 사용하지 않더라도 이 설정은 기본적으로 들어가야 한다.
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    // h2 database 테스트가 원활하도록 관련 API들은 전부 무시한다.
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/h2-console/**", "/favicon.ico");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable() // CRSF 설정 disable

                // exception handling할 때 우리가 만든 클래스를 추가한다
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // h2-console을 위한 설정 추가
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                // Security는 기본적으로 세션을 사용한다.
                // 여기서는 세션 인증이 아니라 토큰인증을 사용할 것이기 때문에 세션 설정을 Stateless로 해준다.
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                // 로그인, 회원가입 API는 토큰이 없는 상태에서 요청이 들어오기 때문에 permitAll
                // 그 외 나머지 요청들은 모두 인증이 필요하다
                .and()
                .authorizeRequests()
                .antMatchers("/auth/**").permitAll()
                .anyRequest().authenticated()

                // JwtFilter를 addFilterBefore로 등록했던 JwtSecurityConfig 클래스를 적용한다
                .and()
                .apply(new JwtSecurityConfig(jwtTokenProvider));
    }
}
