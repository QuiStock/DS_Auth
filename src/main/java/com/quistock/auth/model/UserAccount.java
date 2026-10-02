package com.quistock.auth.model;

public record UserAccount(
    long id, String email, String status, String passwordHash, String roleCode, String roleName) {}
