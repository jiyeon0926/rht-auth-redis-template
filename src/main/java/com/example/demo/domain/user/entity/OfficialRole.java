package com.example.demo.domain.user.entity;

public enum OfficialRole {
    OFFICIAL("민원 처리 공무원"),
    ADMIN("관리자")
    ;

    private final String description;

    OfficialRole(String description) {
        this.description = description;
    }
}
