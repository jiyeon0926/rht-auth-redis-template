package com.example.demo.domain.user.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor
public class AuthRole {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "official_id", nullable = false)
    private Official official;

    @Column(name = "role_name", nullable = false)
    private String name;

    public AuthRole(Official official) {
        this.official = official;
        this.name = OfficialRole.OFFICIAL.name();
    }
}