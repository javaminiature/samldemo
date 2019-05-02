package com.javaminiature.samldemo.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class HomePageController {
	@GetMapping("/home")
	public String login(Model model) {
		Authentication auth =  SecurityContextHolder.getContext().getAuthentication();
		if(auth != null) {
			String username = null;
			Object principal = auth.getPrincipal();
			if (principal instanceof UserDetails) {
				username = ((UserDetails)principal).getUsername();
				} else {
				username = principal.toString();
			 }
			model.addAttribute("user",username);
		    return "homeview";
		} else {
			return "error";					
		}
		
    }

}
