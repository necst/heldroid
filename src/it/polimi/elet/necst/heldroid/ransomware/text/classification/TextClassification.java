package it.polimi.elet.necst.heldroid.ransomware.text.classification;


import java.io.File;
import java.util.*;

public class TextClassification {
    private List<SentenceClassification> sentenceClassifications;
    
    public List<SentenceClassification> getSentenceClassifications() {
        return sentenceClassifications;
    }

    TextClassification(List<SentenceClassification> sentenceClassifications) {
        this.sentenceClassifications = sentenceClassifications;     
    }

    public double maxLikelihood(String category) {
        double max = 0;

        for (SentenceClassification c : sentenceClassifications)
            if (c.getCategory().equals(category) && c.getLikelihood() > max)
                max = c.getLikelihood();

        return max;
    }

    public SentenceClassification containsAnySentence(double minLikelihood, String... categories) {
        List<String> categoryList = Arrays.asList(categories);

        for (SentenceClassification c : sentenceClassifications)
            if (categoryList.contains(c.getCategory()) && c.getLikelihood() >= minLikelihood)
                return c;

        return null;
    }

    public List<SentenceClassification> containsAllSentences(double minLikelihood, String... categories) {
        List<SentenceClassification> list = new ArrayList<SentenceClassification>(categories.length);
        Map<String, Boolean> found = new HashMap<String, Boolean>();
        int foundCount = 0;

        for (SentenceClassification c : sentenceClassifications)
            if ((!found.containsKey(c.getCategory()) || !found.get(c.getCategory())) && c.getLikelihood() >= minLikelihood) {
                found.put(c.getCategory(), true);
                list.add(c);
                foundCount++;

                if (foundCount == categories.length)
                    return list;
            }

        return new ArrayList<SentenceClassification>();
    }

    public List<SentenceClassification> findAllSentences(double minLikelihood, String... categories) {
        List<SentenceClassification> list = new ArrayList<SentenceClassification>();
        List<String> categoryList = Arrays.asList(categories);

        for (SentenceClassification c : sentenceClassifications)
            if (categoryList.contains(c.getCategory()) && c.getLikelihood() >= minLikelihood)
                list.add(c);

        return list;
    }

    public void append(TextClassification other) {
        sentenceClassifications.addAll(other.sentenceClassifications);
    }

    public static TextClassification empty() {
        return new TextClassification(new ArrayList<SentenceClassification>());
    }
}
