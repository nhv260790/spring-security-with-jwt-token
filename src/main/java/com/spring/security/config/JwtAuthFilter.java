package com.spring.security.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.spring.security.repository.UserRepository;

@Component
public class JwtAuthFilter extends OncePerRequestFilter{
	
	private final static String AUTHORIZATION = "authorization";

	private final JwtUtils jwtUtils;
	private final UserRepository userRepository;
	
	
	@Autowired
	public JwtAuthFilter(JwtUtils jwtUtils, UserRepository userRepository) {
		this.jwtUtils = jwtUtils;
		this.userRepository = userRepository;
	}


	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
			FilterChain filterChain)
			throws ServletException, IOException {
		final String authHeader = request.getHeader(AUTHORIZATION);
		final String userEmail;
		final String jwtToken;
		// check authHeader form header
		if(authHeader == null || !authHeader.startsWith("Bearer")) {
			filterChain.doFilter(request, response);
			return;
		}
		// get token from authHeader exclude Bearer words
		jwtToken = authHeader.substring(7);
		
		userEmail = jwtUtils.extractUsername(jwtToken);
		// check in authentication context 
		if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetails = userRepository.findUserDetailsByEmail(userEmail);
			// check token is valid
			if(jwtUtils.isTokenValid(jwtToken, userDetails)) {
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = 
						new UsernamePasswordAuthenticationToken(jwtToken, null, userDetails.getAuthorities());
				WebAuthenticationDetails buildDetails = new WebAuthenticationDetailsSource().buildDetails(request);
				usernamePasswordAuthenticationToken.setDetails(buildDetails);
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
				
			}
		}
		filterChain.doFilter(request, response);
		
	}

}
