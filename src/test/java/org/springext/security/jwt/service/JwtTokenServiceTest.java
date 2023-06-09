package org.springext.security.jwt.service;

import org.junit.jupiter.api.Test;
import org.slf4j.helpers.NOPLogger;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

public class JwtTokenServiceTest {

    private final String signingKeyA = "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345";

    private final String signingKeyB = "98765432109876543210987654321098765432109876543210987654321098765432109876543210987654";

    @Test
    public void testGenerateToken() {
        String userId = UUID.randomUUID().toString();
        JwtConfigurationProperties properties = new JwtConfigurationProperties(signingKeyA, 60,
                "example.com", false, null);
        JwtTokenService jwtTokenService = new JwtTokenService(properties, NOPLogger.NOP_LOGGER);
        String token = jwtTokenService.generateAccessToken(new JwtDetails(userId));
        JwtDetails details = jwtTokenService.getTokenDetails(token);
        assertNotNull(details);
        assertEquals(userId, details.getUserKey());
    }

    @Test
    public void testExpirationDate() {
        JwtConfigurationProperties properties = new JwtConfigurationProperties(signingKeyA, 0,
                "example.com", false, null);
        JwtTokenService jwtTokenService = new JwtTokenService(properties, NOPLogger.NOP_LOGGER);
        String token = jwtTokenService.generateAccessToken(new JwtDetails(UUID.randomUUID().toString()));
        assertNull(jwtTokenService.getTokenDetails(token));
    }

    @Test
    public void testWrongSigningKey() {
        JwtConfigurationProperties properties = new JwtConfigurationProperties(signingKeyA, 60,
                "example.com", false, null);
        JwtTokenService jwtTokenService = new JwtTokenService(properties, NOPLogger.NOP_LOGGER);
        String token = jwtTokenService.generateAccessToken(new JwtDetails(UUID.randomUUID().toString()));
        properties = new JwtConfigurationProperties(signingKeyB, 60,
                "example.com", false, null);
        jwtTokenService = new JwtTokenService(properties, NOPLogger.NOP_LOGGER);
        assertNull(jwtTokenService.getTokenDetails(token));
    }
}
