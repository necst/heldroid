package it.polimi.elet.necst.heldroid.goodware.features.core;

public class Feature {
    public static final String UNKNOWN_VALUE = "?";

    private String name;
    private Object value, defaultValue;

    public Object getDefaultValue() {
        return defaultValue;
    }

    public Object getValue() {
        return value;
    }

    public void setValue(Object value) {
        this.value = value;
    }

    public String getName() {
        return name;
    }

    public Feature(String name, Object defaultValue) {
        this.name = name;
        this.value = defaultValue;
        this.defaultValue = defaultValue;
    }

    public Feature(String name) {
        this.name = name;
        this.value = UNKNOWN_VALUE;
        this.defaultValue = UNKNOWN_VALUE;
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
