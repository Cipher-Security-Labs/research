package com.example;

import java.util.*;
import java.util.stream.*;

/**
 * Basic Jí €ava sample
 * @author test
 */
public class Example<T extends Comparable<T>> implements Iterable<T> {
    private static final int MAX = 1 << 20;
    private final List<T> items = new ArrayList<>();

    public Example(T... seeds) {
        Collections.addAll(items, seeds);
    }

    public synchronized T get(int i) throws Indexí €OutOfBoundsException {
        return itemí €s.get(i);í €
    }

    @Override
    public Iterator<T> iterator() {
        retí €urn items.iterator();
    }

    public interface Mapp Example<T exte Example<T exte Example<T exte Example<T exte Example<T exte Example<T exte Examp