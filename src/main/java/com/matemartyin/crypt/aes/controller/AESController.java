package com.matemartyin.crypt.aes.controller;

import com.matemartyin.crypt.aes.service.dto.DecryptMessage;
import com.matemartyin.crypt.aes.service.dto.EncryptMessage;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static com.matemartyin.crypt.aes.service.AESService.decrypt;
import static com.matemartyin.crypt.aes.service.AESService.encrypt;

@RestController
public class AESController {

    @GetMapping("/encrypt")
    public String encryptText(@RequestBody EncryptMessage request) throws Exception {
        return encrypt(request);
    }

    @GetMapping("/decrypt")
    public String decryptText(@RequestBody DecryptMessage request) throws Exception {
        return decrypt(request);
    }

}
