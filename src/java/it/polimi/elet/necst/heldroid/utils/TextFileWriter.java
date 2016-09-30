package it.polimi.elet.necst.heldroid.utils;

import java.io.*;

public class TextFileWriter extends FileWriter {
    private boolean printOut = false;
    private boolean fileOut = true;

    public void setPrintOut(boolean printOut) {
        this.printOut = printOut;
    }

    public void setFileOut(boolean fileOut) {
        this.fileOut = fileOut;
    }

    public TextFileWriter(File file) throws IOException {
        super(file);
    }

    public void writef(String formatString, Object... args) throws IOException {
        this.write(String.format(formatString, args));
    }

    public void writeln(String text) throws IOException {
        this.write(text);
        this.write("\n");
    }

    public void writeln() throws IOException {
        this.write("\n");
    }

    public void writefln(String formatString, Object... args) throws IOException {
        this.writef(formatString, args);
        this.writeln();
    }

    @Override
    public void write(String s) throws IOException {
        if (this.fileOut)
            super.write(s);

        if (this.printOut)
            System.out.print(s);
    }
}
