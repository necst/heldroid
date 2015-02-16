package it.polimi.elet.necst.heldroid.xml.manifest;

public class StringAttribute {
    private static final String PREFIX = "@string/";

    public static boolean isResourceReference(String attributeValue) {
        return attributeValue.startsWith(PREFIX);
    }

    public static String getReferenceName(String resourceReference) {
        if (resourceReference.length() < PREFIX.length())
            return "";

        return resourceReference.substring(PREFIX.length());
    }
}
