package com.spring.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.spring.security.config.JwtUtils;
import com.spring.security.dto.AuthenticationRequest;
import com.spring.security.repository.UserRepository;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {
	
	private final AuthenticationManager authenticationManager;
	private final JwtUtils jwtUtils;
	private final UserRepository userRepository;
	
	
	@Autowired
	public AuthenticationController(AuthenticationManager authenticationManager, JwtUtils jwtUtils, UserRepository userRepository) {
		this.authenticationManager = authenticationManager;
		this.jwtUtils = jwtUtils;
		this.userRepository = userRepository;
	}


	@PostMapping("/authenticate")
	public ResponseEntity<String> authenticate(@RequestBody AuthenticationRequest request){
		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = 
				new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword());
		authenticationManager.authenticate(usernamePasswordAuthenticationToken);
		UserDetails userDetails = userRepository.findUserDetailsByEmail(request.getEmail());
		if (userDetails != null) {
			return ResponseEntity.ok(jwtUtils.generateToken(userDetails));
		}
		return ResponseEntity.status(400).body("Can not authenticate");
	}
}
