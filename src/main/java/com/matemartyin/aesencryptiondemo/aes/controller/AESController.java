package com.matemartyin.aesencryptiondemo.aes.controller;

import com.matemartyin.aesencryptiondemo.aes.service.AESService;
import com.matemartyin.aesencryptiondemo.aes.service.dto.DecryptMessage;
import com.matemartyin.aesencryptiondemo.aes.service.dto.EncryptMessage;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class AESController {

    @GetMapping("/")
    public String encryptText(@ModelAttribute EncryptMessage encryptMessage, @ModelAttribute DecryptMessage decryptMessage, Model model) throws Exception {
        model.addAttribute("encrypted", null);
        return "home";
    }

    @PostMapping("/encrypt")
    public String encrypt(@ModelAttribute EncryptMessage encryptMessage, @ModelAttribute DecryptMessage decryptMessage, Model model) throws Exception {
        model.addAttribute("encrypted", AESService.encrypt(encryptMessage));
        return "home";
    }

    @PostMapping("/decrypt")
    public String decrypt(@ModelAttribute EncryptMessage encryptMessage, @ModelAttribute DecryptMessage decryptMessage, Model model) throws Exception {
        model.addAttribute("decrypted", AESService.decrypt(decryptMessage));
        return "home";
    }

}
