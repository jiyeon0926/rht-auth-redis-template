package com.example.demo.domain.user.controller;

import com.example.demo.domain.user.dto.UserSignupReqDto;
import com.example.demo.domain.user.dto.UserSignupResDto;
import com.example.demo.domain.user.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<UserSignupResDto> userSignup(@Valid @RequestBody UserSignupReqDto userSignupReqDto) {
        UserSignupResDto userSignup = userService.userSignup(userSignupReqDto.getEmail(), userSignupReqDto.getPassword(), userSignupReqDto.getName());

        return new ResponseEntity<>(userSignup, HttpStatus.CREATED);
    }
}
