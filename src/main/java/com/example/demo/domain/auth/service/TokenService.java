package com.example.demo.domain.auth.service;

import com.example.demo.global.auth.jwt.JwtProvider;
import com.example.demo.global.common.constants.TokenConstants;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final StringRedisTemplate redisTemplate;
    private final JwtProvider jwtProvider;

    // 이메일을 Key로 가지는 Refresh 토큰 저장
    public void saveRefreshToken(String refreshToken, String email) {
        Claims claims = jwtProvider.getClaims(refreshToken);
        long expiration = claims.getExpiration().getTime();

        redisTemplate.opsForValue().set(
                TokenConstants.REFRESH_TOKEN_KEY + email,
                refreshToken,
                expiration,
                TimeUnit.MILLISECONDS
        );
    }

    public void deleteRefreshToken(String email) {
        String key = TokenConstants.REFRESH_TOKEN_KEY + email;
        redisTemplate.delete(key);
    }

    public String getRefreshToken(String email) {
        String key = TokenConstants.REFRESH_TOKEN_KEY + email;

        return redisTemplate.opsForValue().get(key);
    }

    public void validRefreshToken(String email, String refreshToken) {
        String token = getRefreshToken(email);

        if (token == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh Token이 존재하지 않습니다.");
        }

        if (!token.equals(refreshToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "유효하지 않은 Refresh Token입니다.");
        }
    }
}
