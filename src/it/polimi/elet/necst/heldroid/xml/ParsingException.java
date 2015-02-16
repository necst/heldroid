package it.polimi.elet.necst.heldroid.xml;

/**
 * Created by Nicolo on 04/02/14.
 */
public class ParsingException extends Exception {
    public ParsingException(Throwable cause) {
        super(cause);
    }

    public ParsingException(String message) {
        super(message);
    }
}
