package com.example.springjwtauthentication.repository;

import com.example.springjwtauthentication.entity.Role;
import com.example.springjwtauthentication.enums.ERole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
