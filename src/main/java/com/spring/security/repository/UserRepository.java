package com.spring.security.repository;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository {
	
	private final static List<UserDetails> APP_USERS = Arrays.asList(
			new User("viet@gmail.com", "password", Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN")) ),
			new User("diem@gmail.com", "password", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")))
			);
	
	public UserDetails findUserDetailsByEmail(String email) {
		return APP_USERS
				.stream()
				.filter(u -> u.getUsername().equalsIgnoreCase(email))
				.findFirst()
				.orElseThrow(() -> new UsernameNotFoundException("Can not find username with email " + email ));
	}

}
