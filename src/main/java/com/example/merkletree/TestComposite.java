package com.example.merkletree;

import java.util.List;

import lombok.Data;

@Data
public class TestComposite {

    private String content = "";
    private List<TestComposite> children;

    public TestComposite(List<TestComposite> children) {
        this.children = children;
        generateRandomContent();
    }

    private void generateRandomContent() {
        int length = randomInt();
        for (int i = 0; i < length; i++) {
            content += String.valueOf(randomInt());
        }
    }

    private int randomInt() {
        return (int) (Math.random() * 100);
    }
}
