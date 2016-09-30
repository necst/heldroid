package it.polimi.elet.necst.heldroid.ransomware.text.classification;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class StopWordList implements StopWordCollection {
    private String[] stopwords;

    private StopWordList(List<String> list) {
        this.stopwords = new String[list.size()];
        for (int i = 0; i < list.size(); i++)
            this.stopwords[i] = list.get(i);
    }

    public boolean contains(String word) {
        return (word.length() <= 1) || (Arrays.binarySearch(this.stopwords, word) >= 0);
    }

    public static StopWordList fromFile(File source) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(source));
            List<String> stopwordList = new ArrayList<String>();
            String word = null;

            while ((word = reader.readLine()) != null)
                stopwordList.add(word);

            reader.close();

            Collections.sort(stopwordList);

            return new StopWordList(stopwordList);
        } catch (IOException e) {
            return null;
        }
    }
}
