package com.sparta.springauth.controller;

import com.sparta.springauth.entity.User;
import com.sparta.springauth.security.UserDetailsImpl;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/api")
public class ProductController {

    @GetMapping("/products")
    public String getProducts(@AuthenticationPrincipal UserDetailsImpl userDetails) {
        // Authentication 의 Principal 에서 UserDetails 가져오는 것.
        User user = userDetails.getUser();
        System.out.println("user.getUsername() = " + user.getUsername());

        return "redirect:/";
    }
}