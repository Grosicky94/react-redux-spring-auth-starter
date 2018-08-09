package com.example.spring.server.utils;

public final class Constants {

    private Constants() {
        // restrict instantiation
    }

    public static final String SESSION_COOKIE_NAME = "_sid";
    public static final String JWT_SECRET = "SecretKeyToGenJWTs";
    public static final long EXPIRATION_TIME = 864_000_000; // 10 days
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";
    public static final String REGISTER_URL = "/user/register";
    public static final String SIGN_IN_URL = "/user/signin";
}