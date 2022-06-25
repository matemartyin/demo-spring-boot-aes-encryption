package com.matemartyin.aesencryptiondemo.aes.service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Builder
@Getter
@Setter
public class DecryptMessage {
    public String cipherText;
    public String password;
}
