package it.polimi.elet.necst.heldroid.xml.resources;

public class StringResourceParsers {
    private static DomStringResourceParser domParser;

    public static StringResourceParser domBased() {
        if (domParser != null)
            return domParser;

        domParser = new DomStringResourceParser();
        return domParser;
    }
}
