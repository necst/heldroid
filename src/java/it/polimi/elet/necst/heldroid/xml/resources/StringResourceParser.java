package it.polimi.elet.necst.heldroid.xml.resources;

import it.polimi.elet.necst.heldroid.xml.ParsingException;

import java.io.File;

public interface StringResourceParser {
    StringResource parse(File resourceFile) throws ParsingException;
}
