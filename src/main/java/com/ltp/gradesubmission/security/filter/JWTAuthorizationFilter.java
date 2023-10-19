package com.ltp.gradesubmission.security.filter;

import java.io.IOException;
import java.util.Arrays;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Header;
import com.ltp.gradesubmission.security.SecurityConstants;

public class JWTAuthorizationFilter extends OncePerRequestFilter{

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // TODO Auto-generated method stub
       String header = request.getHeader("Authorization");
       if (header == null || !header.startsWith(SecurityConstants.BEARER)) {
        filterChain.doFilter(request,response);
        return;
       }
       String bearerToken = header.replace(SecurityConstants.BEARER, "");
       String user = JWT.require(Algorithm.HMAC512(SecurityConstants.SECRET_KEY)).build().verify(bearerToken).getSubject();
       Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, Arrays.asList());
       SecurityContextHolder.getContext().setAuthentication(authentication);
       filterChain.doFilter(request, response);
    }
    
}
