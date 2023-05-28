package com.example.auth0.controller;

import com.auth0.AuthenticationController;
import com.auth0.IdentityVerificationException;
import com.auth0.Tokens;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.auth0.config.SecurityConfig;
import com.example.auth0.domain.User;
import com.example.auth0.service.UserDetailServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.List;

@Controller
public class AuthController {

    @Autowired
    private AuthenticationController authenticationController;

    @Autowired
    private SecurityConfig config;

    @Value(value = "${app.redirectUri}")
    private String redirectUri;

    @Autowired
    JwtDecoder jwtDecoder;

    @Autowired
    UserDetailServiceImpl userDetailService;

    @GetMapping(value = "/login")
    protected void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUri = config.getContextPath(request) + "/callback";
        String authorizeUrl = authenticationController.buildAuthorizeUrl(request, response, redirectUri)
                .withScope("openid email")
                .build();
        response.sendRedirect(authorizeUrl);
    }

    @GetMapping(value = "/callback")
    public void callback(HttpServletRequest request, HttpServletResponse response) throws IOException, IdentityVerificationException {
        Tokens tokens = authenticationController.handle(request, response);

//
        Jwt jwt = null;
        try {
            // Validate token
            jwt = jwtDecoder.decode(tokens.getIdToken());

        } catch (Exception e) {
            e.printStackTrace();
        }


        String email = jwt.getClaim("email");

        if (email != null) {
            User userDetails = (User) userDetailService.loadUserByUsername(email);

            if(userDetails == null) {
                response.sendRedirect("/login");
                return;
            }

            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities()
            );

            authToken.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
            );
            SecurityContextHolder.getContext().setAuthentication(authToken);
            response.sendRedirect(redirectUri+"?token="+tokens.getIdToken());
            return;
        }

        response.sendRedirect("/login");
    }

}