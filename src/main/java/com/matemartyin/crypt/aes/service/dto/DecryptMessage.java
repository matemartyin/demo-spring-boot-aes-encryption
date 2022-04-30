package com.matemartyin.crypt.aes.service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;

@AllArgsConstructor
@Builder
public class DecryptMessage {
    public String cipherText;
    public String password;
}
