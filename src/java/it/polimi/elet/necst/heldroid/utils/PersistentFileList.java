package it.polimi.elet.necst.heldroid.utils;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class PersistentFileList {
    private List<String> innerList;
    private BufferedWriter writer;

    public PersistentFileList(File repo) throws IOException {
        innerList = new ArrayList<String>();

        if (repo.exists()) {
            BufferedReader reader = new BufferedReader(new FileReader(repo));
            String line;

            while ((line = reader.readLine()) != null)
                innerList.add(line);

            reader.close();
        }

        writer = new BufferedWriter(new FileWriter(repo, true)); // append to repo, if it exists
    }

    public synchronized void add(File file) {
        innerList.add(file.getAbsolutePath());

        try {
            writer.write(file.getAbsolutePath());
            writer.newLine();
            writer.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public synchronized boolean contains(File file) {
        return innerList.contains(file.getAbsolutePath());
    }

    public synchronized void dispose() {
        try {
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
