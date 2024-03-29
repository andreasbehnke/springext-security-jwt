package org.springext.security.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springext.security.jwt.dto.UserAuthenticationRequest;
import org.springext.security.jwt.dto.UserView;
import org.springext.security.jwt.service.JwtDetails;
import org.springext.security.jwt.service.JwtTokenService;
import org.springext.security.jwt.userdetails.UserAuthenticationDetails;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;

public class JsonUsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final JwtTokenService jwtTokenService;

    private final ObjectMapper objectMapper;

    public JsonUsernamePasswordAuthenticationFilter(
            RequestMatcher requiresAuthenticationRequestMatcher,
            ObjectMapper objectMapper,
            JwtTokenService jwtTokenService,
            AuthenticationManager authenticationManager) {
        super(requiresAuthenticationRequestMatcher);
        setAuthenticationManager(authenticationManager);
        this.objectMapper = objectMapper;
        this.jwtTokenService = jwtTokenService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        try {
            UserAuthenticationRequest userAuthenticationRequest = objectMapper.readValue(request.getInputStream(), UserAuthenticationRequest.class);
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                    userAuthenticationRequest.getUsername(), userAuthenticationRequest.getPassword());
            Authentication authentication = this.getAuthenticationManager().authenticate(authRequest);
            UserAuthenticationDetails authDetails = (UserAuthenticationDetails) authentication.getPrincipal();
            jwtTokenService.setToken(response, new JwtDetails(authDetails.getUserKey()));
            objectMapper.writeValue(response.getOutputStream(), new UserView(authDetails.getUserKey(), authDetails.getUsername()));
            return authentication;
        } catch (IOException e) {
            throw new AuthenticationServiceException("Could not read JSON object from input stream", e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) {
        // do nothing, simply return with authorization header or cookie
    }
}
