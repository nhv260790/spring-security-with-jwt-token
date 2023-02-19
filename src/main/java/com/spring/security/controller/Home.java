package com.spring.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class Home {
	@GetMapping("home")
	public String home() {
		return "This is home page";
	}
	
	@GetMapping("detail")
	public String detail() {
		return "This is detail page";
	}
}
