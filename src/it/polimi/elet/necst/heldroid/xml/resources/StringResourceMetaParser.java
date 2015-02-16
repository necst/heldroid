package it.polimi.elet.necst.heldroid.xml.resources;

import it.polimi.elet.necst.heldroid.xml.ParsingException;

import java.io.File;

public class StringResourceMetaParser {
    private StringResourceParser basicParser;

    public StringResourceMetaParser(StringResourceParser basicParser) {
        this.basicParser = basicParser;
    }

    public StringResource parseDirectory(File directory) {
        StringResource finalResult = new StringDictionary();

        for (File file : directory.listFiles()) {
            if (file.isDirectory())
                finalResult = finalResult.merge(this.parseDirectory(file));

            if (!file.getName().endsWith(".xml"))
                continue;

            try {
                StringResource res = basicParser.parse(file);
                finalResult = finalResult.merge(res);
            } catch (ParsingException pe) {
                continue;
            }
        }

        return finalResult;
    }
}
