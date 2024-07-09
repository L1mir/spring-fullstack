package com.limir.springfullstack.model;

import jakarta.persistence.*;
import jakarta.persistence.GenerationType;
import lombok.Data;

@Entity
@Table(name = "users")
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    private String username;
    @Column
    private String password;
    @Column
    private String email;
}
