package com.example.merkletree;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

@SpringBootApplication
@Slf4j
public class MerkleTreesApplication {

    public static void main(String[] args) {
        SpringApplication.run(MerkleTreesApplication.class, args);
    }

    public static final String PROVIDER_NAME = "BC";

    @PostConstruct
    public void setup() {
        setupCrypto();
    }

    public void setupCrypto() {

        Security.addProvider(new BouncyCastleProvider());

        if (Security.getProvider(PROVIDER_NAME) == null) {
            log.error("Bouncy Castle provider is not installed");
        } else {
            log.info("Bouncy Castle provider is installed.");
        }

        Security.setProperty("crypto.policy", "unlimited");
    }

}
