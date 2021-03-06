package com.example.springjwtauthentication.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtModel {

    private String token;
    private final String type = "Bearer";
    private Long id;
    private String username;
    private String name;
    private List<String> roles;

}