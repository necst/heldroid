package it.polimi.elet.necst.heldroid.csv;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class CsvWriter {
    private boolean lineStarted;
    private String separator;
    private BufferedWriter writer;

    public CsvWriter(File file) throws IOException {
        this(file, false);
    }

    public CsvWriter(File file, boolean append) throws IOException {
        this.writer = new BufferedWriter(new FileWriter(file, append));
        this.lineStarted = false;
        this.separator = ", ";
    }

    public synchronized void writeField(String value) {
        try {
            if (lineStarted)
                writer.write(separator);

            writer.write(value);
            lineStarted = true;
        } catch (IOException ioex) {
            ioex.printStackTrace();
        }
    }

    public synchronized void writeField(Object value)  {
        this.writeField(value.toString());
    }

    public synchronized void close() {
        try {
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public synchronized void newRecord()  {
        try {
            lineStarted = false;
            writer.newLine();
            writer.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String getSeparator() {
        return separator;
    }

    public void setSeparator(String separator) {
        if (separator != null)
            this.separator = separator;
    }
}
