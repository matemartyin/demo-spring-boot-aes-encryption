package com.matemartyin.crypt.aes.service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;

@AllArgsConstructor
@Builder
public class EncryptMessage {
    public String plainText;
    public String password;
}
