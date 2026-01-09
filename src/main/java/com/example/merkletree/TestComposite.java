package com.example.merkletree;

import java.util.List;

import lombok.Data;

@Data
public class TestComposite {

    private List<TestObject> leafChildren;

    private List<TestComposite> compositeChildren;

    public TestComposite(List<TestObject> testObjects, List<TestComposite> testComposites) {
        this.leafChildren = testObjects;
        this.compositeChildren = testComposites;
    }

}
