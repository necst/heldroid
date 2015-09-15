package it.polimi.elet.necst.heldroid.ransomware.text.classification;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class GenericTextClassifier implements TextClassifier {
    private Segmenter segmenter;
    private Map<String, List<StemVector>> basis;

    public GenericTextClassifier(Segmenter segmenter) {
        this.segmenter = segmenter;
        this.basis = new HashMap<String, List<StemVector>>();
    }

    public void teach(String category, String text) {
        List<Segmenter.StemmedSentence> stemmedSentences = segmenter.segment(text);
        List<StemVector> categoryVectors = this.basis.get(category);

        if (categoryVectors == null)
            this.basis.put(category, (categoryVectors = new ArrayList<StemVector>()));

        for (Segmenter.StemmedSentence stemmedSentence : stemmedSentences)
            categoryVectors.add(new StemVector(stemmedSentence.getStems()));
    }

    public TextClassification classify(String text) {
        List<SentenceClassification> sentenceClassifications = new ArrayList<SentenceClassification>();
        List<Segmenter.StemmedSentence> stemmedSentences = segmenter.segment(text);

        for (Segmenter.StemmedSentence stemmedSentence : stemmedSentences) {
            StemVector sentenceVector = new StemVector(stemmedSentence.getStems());
            String bestCategory = "<UNDEFINED>";
            double bestSimilarity = 0;

            for (Map.Entry<String, List<StemVector>> entry : this.basis.entrySet()) {
                String category = entry.getKey();
                List<StemVector> categoryVectors = entry.getValue();

                for (StemVector categoryVector : categoryVectors) {
                    double similarity = categoryVector.cosineSimilarity(sentenceVector);
                    if (similarity >= bestSimilarity) {
                        bestCategory = category;
                        bestSimilarity = similarity;
                    }
                }
            }

            SentenceClassification sentenceClassification = new SentenceClassification();
            sentenceClassification.setCategory(bestCategory);
            sentenceClassification.setLikelihood(bestSimilarity);
            sentenceClassification.setText(stemmedSentence.getOriginalText());
            sentenceClassification.setProducedStemsCount(sentenceVector.stems.size());

            sentenceClassifications.add(sentenceClassification);
        }

        return new TextClassification(sentenceClassifications);
    }

    private static class StemVector {
        private Set<String> stems;

        public StemVector(Set<String> stems) {
            this.stems = stems;
        }

        public double cosineSimilarity(StemVector other) {
            Set<String> smaller, bigger;

            if (this.stems.size() < other.stems.size()) {
                smaller = this.stems;
                bigger = other.stems;
            } else {
                smaller = other.stems;
                bigger = this.stems;
            }

            int intersectionSize = 0;

            for (String stem : smaller)
                if (bigger.contains(stem))
                    intersectionSize++;

            return (double)intersectionSize / (Math.sqrt(smaller.size()) * Math.sqrt(bigger.size()));
        }
    }

    public static class Match {
        private String category;
        private double similarity;

        public String getCategory() {
            return category;
        }

        private void setCategory(String category) {
            this.category = category;
        }

        public double getSimilarity() {
            return similarity;
        }

        private void setSimilarity(double similarity) {
            this.similarity = similarity;
        }
    }
}
