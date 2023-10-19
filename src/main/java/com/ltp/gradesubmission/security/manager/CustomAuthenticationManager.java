package com.ltp.gradesubmission.security.manager;

import java.beans.JavaBean;

import org.aspectj.weaver.bcel.BcelAccessForInlineMunger;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import com.ltp.gradesubmission.entity.User;
import com.ltp.gradesubmission.service.UserService;

import lombok.AllArgsConstructor;

@AllArgsConstructor
@Component
public class CustomAuthenticationManager implements AuthenticationManager {

    private UserService userService;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // TODO Auto-generated method stub
        User user = userService.getUser(authentication.getName());
      if (!bCryptPasswordEncoder.matches(authentication.getCredentials().toString(), user.getPassword())) {
        throw  new BadCredentialsException("Wrong Pasword");
      }
      return new UsernamePasswordAuthenticationToken(authentication.getName(), user.getPassword());
    }

}
