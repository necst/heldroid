package it.polimi.elet.necst.heldroid.utils;

public class Literal {
    public static boolean isString(String liteal) {
        return liteal.startsWith("\"");
    }

    public static String getStringValue(String literal) {
        return literal.replace("\"", "");
    }
}
