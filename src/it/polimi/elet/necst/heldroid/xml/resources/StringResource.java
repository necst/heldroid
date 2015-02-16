package it.polimi.elet.necst.heldroid.xml.resources;

import java.util.Collection;

public interface StringResource {
    Collection<String> getAllNames();
    String getValue(String name);
    StringResource merge(StringResource resource);
    Boolean isEmpty();
}
