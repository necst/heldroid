package it.polimi.elet.necst.heldroid.xml.resources;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

class StringDictionary implements StringResource {
    private Map<String, String> map;

    public StringDictionary() {
        this.map = new HashMap<String, String>();
    }

    public void add(String name, String value) {
        this.map.put(name, value);
    }

    @Override
    public Collection<String> getAllNames() {
        return this.map.keySet();
    }

    @Override
    public String getValue(String name) {
        return this.map.get(name);
    }

    @Override
    public StringResource merge(StringResource resource) {
        StringDictionary result = new StringDictionary();

        result.map.putAll(this.map);

        for (String name : resource.getAllNames())
            result.map.put(name, resource.getValue(name));

        return result;
    }

    @Override
    public Boolean isEmpty() {
        return (this.map.size() == 0);
    }
}
