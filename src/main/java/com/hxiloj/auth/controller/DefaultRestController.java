package com.hxiloj.auth.controller;

import java.security.Principal;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/rest/user")
public class DefaultRestController {

    @GetMapping
    public String hello() {
        return "Hello Henry user";
    }
    
	@GetMapping("/principal")
    public Principal user(Principal principal) {
        return principal;
    }
	
}
