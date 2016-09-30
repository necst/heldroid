package it.polimi.elet.necst.heldroid.utils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class MultiMap<K, V> {
    private Map<K, Collection<V>> map;

    public MultiMap() {
        map = new HashMap<K, Collection<V>>();
    }

    public void put(K name, V value) {
        Collection<V> existingCollection = map.get(name);

        if (existingCollection != null) {
            existingCollection.add(value);
        } else {
            Collection<V> newCollection = new ArrayList<V>();
            newCollection.add(value);
            map.put(name, newCollection);
        }
    }

    public void putAll(K name, Collection<V> values) {
        Collection<V> existingCollection = map.get(name);

        if (existingCollection != null) {
            existingCollection.addAll(values);
        } else {
            Collection<V> newCollection = new ArrayList<V>();
            newCollection.addAll(values);
            map.put(name, newCollection);
        }
    }

    public void replaceAll(K name, Collection<V> values) {
        Collection<V> existingColletion = map.get(name);

        if (existingColletion != null) {
            existingColletion.clear();
            existingColletion.addAll(values);
        } else {
            Collection<V> newCollection = new ArrayList<V>();
            newCollection.addAll(values);
            map.put(name, newCollection);
        }
    }

    public void empty(K name) {
        Collection<V> existingColletion = map.get(name);

        if (existingColletion != null)
            existingColletion.clear();
    }

    public Collection<V> get(K name) {
        if (map.containsKey(name))
            return map.get(name);

        return map.put(name, new ArrayList<V>());
    }

    public boolean containsKey(K name) {
        return map.containsKey(name);
    }
}
