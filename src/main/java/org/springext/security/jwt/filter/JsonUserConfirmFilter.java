package org.springext.security.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springext.security.jwt.dto.UserConfirmRequest;
import org.springext.security.jwt.dto.UserRegistrationRequest;
import org.springext.security.jwt.dto.UserRegistrationResult;
import org.springext.security.jwt.dto.UserRegistrationResultMessage;
import org.springext.security.jwt.userdetails.UserAuthenticationDetails;
import org.springext.security.jwt.userdetails.UserAuthenticationDetailsService;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

public class JsonUserConfirmFilter<U extends UserAuthenticationDetails, R extends UserRegistrationRequest> extends GenericFilterBean {

    private final RequestMatcher requestMatcher;

    private final ObjectMapper objectMapper;

    private final UserAuthenticationDetailsService<U,R> userAuthenticationDetailsService;

    public JsonUserConfirmFilter(RequestMatcher requestMatcher, ObjectMapper objectMapper, UserAuthenticationDetailsService<U,R> userAuthenticationDetailsService) {
        this.requestMatcher = requestMatcher;
        this.objectMapper = objectMapper;
        this.userAuthenticationDetailsService = userAuthenticationDetailsService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (requestMatcher.matches(request) && request.getMethod().equals("POST")) {
            UserConfirmRequest userConfirmRequest = objectMapper.readValue(request.getInputStream(), UserConfirmRequest.class);
            UserRegistrationResult result = confirmTicket(userConfirmRequest);
            if (result.getMessage() != UserRegistrationResultMessage.REGISTRATION_CONFIRMED) {
                response.setStatus(HttpServletResponse.SC_CONFLICT);
            }
            objectMapper.writeValue(response.getOutputStream(), result);
        } else {
            chain.doFilter(request, response);
        }
    }

    private UserRegistrationResult confirmTicket(UserConfirmRequest userConfirmRequest) {
       return userAuthenticationDetailsService.confirmRegistrationTicket(userConfirmRequest.getTicketId())
               .map(u -> UserRegistrationResult.registrationConfirmed(u.getUsername()))
               .orElse(UserRegistrationResult.invalidConfirmTicket());
    }
}
