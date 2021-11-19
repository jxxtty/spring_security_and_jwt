package com.example.securityAndJWT.service;

import com.example.securityAndJWT.domain.Member;
import com.example.securityAndJWT.domain.RefreshToken;
import com.example.securityAndJWT.domain.dto.MemberRequestDto;
import com.example.securityAndJWT.domain.dto.MemberResponseDto;
import com.example.securityAndJWT.domain.dto.TokenDto;
import com.example.securityAndJWT.domain.dto.TokenRequestDto;
import com.example.securityAndJWT.repository.MemberRepository;
import com.example.securityAndJWT.repository.RefreshTokenRepository;
import com.example.securityAndJWT.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Service
public class AuthService {
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    // 유저 정보를 받아서 저장한다
    @Transactional
    public MemberResponseDto signup(MemberRequestDto memberRequestDto) {
        if (memberRepository.existsByEmail(memberRequestDto.getEmail())) {
            throw new RuntimeException("이미 가입되어있는 유저입니다");
        }

        Member member = memberRequestDto.toMember(passwordEncoder);
        return MemberResponseDto.of(memberRepository.save(member));
    }


    @Transactional
    public TokenDto login(MemberRequestDto memberRequestDto) {
        // 1. Login Id/Pw를 기반으로 AuthenticationToken 생성
        UsernamePasswordAuthenticationToken authenticationToken = memberRequestDto.toAuthentication();

        // 2. 실제로 검증 (사용자 비밀번호 체크)이 이뤄지는 부분
        // authentication 메서드가 실행이 될 때 CustomUserDetailService에서 만들었던 loadUserByUsername 메서드가 실행된다.
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(authentication);

        // 4. refreshToken 생성 및 저장
        RefreshToken refreshToken = RefreshToken.builder()
                .key(authentication.getName())
                .value(tokenDto.getRefreshToken())
                .build();

        refreshTokenRepository.save(refreshToken);

        // 5. 토큰 발급
        // refresh token은 저장하고 생성된 토큰정보는 클라이언트에게 전달한다.
        return tokenDto;
    }

    // Access Token 과 Refresh Token을 ResponseBody에서 받아서 검증한다.
    @Transactional
    public TokenDto reissue(TokenRequestDto tokenRequestDto) {
        // Refresh Token의 만료 여부를 먼저 검사
        // 1. refresh token 검증
        if (!jwtTokenProvider.validateToken(tokenRequestDto.getRefreshToken())) {
            throw new RuntimeException("Refresh Token이 유효하지 않습니다");
        }

        // Access Token을 복호화하여 유저 정보(memberId)를 가져오고, 저장소에 있는 Refresh Token과 클라이언트가 전달한 refresh token의 일치여부를 검사
        // 2. Access Token 에서 Member Id 가져오기
        Authentication authentication = jwtTokenProvider.getAuthentication(tokenRequestDto.getAccessToken());

        // 3. 저장소에서 Member ID 를 기반으로 Refresh Token 값을 가져온다
        RefreshToken refreshToken = refreshTokenRepository.findByKey(authentication.getName())
                                                    .orElseThrow(() -> new RuntimeException("로그아웃 된 사용자입니다."));

        // 4. RefreshToken 일치하는지 검사
        if (!refreshToken.getValue().equals(tokenRequestDto.getRefreshToken())) {
            throw new RuntimeException("토큰의 유저 정보가 일치하지 않습니다.");
        }

        // 5. 새로운 토큰 생성
        TokenDto tokenDto = jwtTokenProvider.generateTokenDto(authentication);

        // 6. 저장소 정보 업데이트(refreshToken 갱신)
        RefreshToken newRefreshToken = refreshToken.updateValue(tokenDto.getRefreshToken());
        refreshTokenRepository.save(newRefreshToken);

        // 7. 토큰 발급
        return tokenDto;

    }
}
