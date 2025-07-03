package com.example.demo.domain.user.controller;

import com.example.demo.domain.user.dto.UserSignupReqDto;
import com.example.demo.domain.user.dto.UserSignupResDto;
import com.example.demo.domain.user.service.OfficialService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admins")
@RequiredArgsConstructor
public class OfficialController {

    private final OfficialService officialService;

    @PostMapping("/signup")
    public ResponseEntity<UserSignupResDto> adminSignup(@Valid @RequestBody UserSignupReqDto userSignupReqDto) {
        UserSignupResDto adminSignup = officialService.adminSignup(userSignupReqDto.getEmail(), userSignupReqDto.getPassword(), userSignupReqDto.getName());

        return new ResponseEntity<>(adminSignup, HttpStatus.CREATED);
    }
}
