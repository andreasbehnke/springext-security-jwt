package org.springext.security.jwt;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Date;

/**
 * Provides methods for generating and validating JSON Web Tokens.
 */
@Component
public class JwtTokenService {

    public static final String BEARER = "Bearer ";

    private final Logger logger;

    private final String jwtSigningKey;

    private final int jwtExpirationTimeInSeconds;

    private final String jwtIssuer;

    private boolean useCookie;

    private String cookieName;

    public JwtTokenService(
            @Value("${authentication.jwt.signingKey}") String jwtSigningKey,
            @Value("${authentication.jwt.expirationTimeInSeconds}") int jwtExpirationTimeInSeconds,
            @Value("${authentication.jwt.issuer}") String jwtIssuer,
            @Value("${authentication.jwt.useCookie}") boolean useCookie,
            @Value("${authentication.jwt.cookieName}") String cookieName,
            Logger logger) {
        this.jwtSigningKey = jwtSigningKey;
        this.jwtExpirationTimeInSeconds = jwtExpirationTimeInSeconds;
        this.jwtIssuer = jwtIssuer;
        this.useCookie = useCookie;
        this.cookieName = cookieName;
        this.logger = logger;
    }

    JwtDetails getTokenDetails(String token) {
        try {
            Claims claims = Jwts.parser().setSigningKey(jwtSigningKey)
                    .parseClaimsJws(token).getBody();
            return new JwtDetails(claims.getSubject());
        } catch (SignatureException ex) {
            logger.error("Invalid JWT signature - {}", ex.getMessage());
        } catch (MalformedJwtException | IllegalArgumentException ex) {
            logger.error("Invalid JWT token - {}", ex.getMessage());
        } catch (ExpiredJwtException ex) {
            logger.warn("Expired JWT token - {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token - {}", ex.getMessage());
        }
        return null;
    }

    String generateAccessToken(JwtDetails details) {
        Assert.notNull(details, "Parameter details must not be null");
        return Jwts.builder()
                .setSubject(details.getUserKey())
                .setIssuer(jwtIssuer)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + (long)jwtExpirationTimeInSeconds * 1000))
                .signWith(SignatureAlgorithm.HS512, jwtSigningKey)
                .compact();
    }

    public JwtDetails getTokenDetails(HttpServletRequest request) {
        if (useCookie) {
            return getTokenDetailsFromCookie(request);
        } else {
            return getTokenDetailsFromHeader(request);
        }
    }

    private JwtDetails getTokenDetailsFromHeader(HttpServletRequest request) {
        final String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (!StringUtils.hasText(header) || !header.startsWith("Bearer ")) {
            throw new BadCredentialsException("JWT header is missing");
        }

        String token =  StringUtils.split(header, " ")[1];
        JwtDetails jwtDetails = getTokenDetails(token);
        if (jwtDetails == null) {
            throw new BadCredentialsException("JWT token could not be parsed");
        }
        return jwtDetails;
    }

    private JwtDetails getTokenDetailsFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            throw new BadCredentialsException("JWT cookie is missing");
        }
        Cookie cookie = Arrays.stream(cookies)
                .filter(c -> c.getName().equals(cookieName))
                .findFirst()
                .orElseThrow(() -> new BadCredentialsException("JWT cookie is missing"));

        JwtDetails jwtDetails = getTokenDetails(cookie.getValue());
        if (jwtDetails == null) {
            throw new BadCredentialsException("JWT token could not be parsed");
        }
        return jwtDetails;
    }

    public void setToken(HttpServletResponse response, JwtDetails jwtDetails) {
        if (useCookie) {
            setTokenCookie(response, jwtDetails);
        } else {
            setTokenToHeader(response, jwtDetails);
        }
    }

    private void setTokenToHeader(HttpServletResponse response, JwtDetails jwtDetails) {
        // this will reset token expiration
        String freshToken = generateAccessToken(jwtDetails);
        response.setHeader(HttpHeaders.AUTHORIZATION, BEARER + freshToken);
    }

    private void setTokenCookie(HttpServletResponse response, JwtDetails jwtDetails) {
        // this will reset token expiration
        String freshToken = generateAccessToken(jwtDetails);
        Cookie cookie = new Cookie(cookieName, freshToken);
        //TODO: Make Domain, Path and Secure configurable!
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(jwtExpirationTimeInSeconds);
        response.addCookie(cookie);
    }
}
