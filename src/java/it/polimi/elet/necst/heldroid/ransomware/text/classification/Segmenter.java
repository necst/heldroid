package it.polimi.elet.necst.heldroid.ransomware.text.classification;

import opennlp.tools.sentdetect.SentenceDetector;
import opennlp.tools.stemmer.Stemmer;
import opennlp.tools.tokenize.SimpleTokenizer;
import opennlp.tools.tokenize.Tokenizer;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Segmenter {
    private static final Pattern whitespaces = Pattern.compile("\\s+");

    private StopWordCollection stopWordCollection;
    private Stemmer stemmer;
    private SentenceDetector sentenceDetector;
    private Tokenizer tokenizer;

    public Segmenter(StopWordCollection stopWordCollection, Stemmer stemmer, SentenceDetector sentenceDetector) {
        this.stopWordCollection = stopWordCollection;
        this.stemmer = stemmer;
        this.sentenceDetector = sentenceDetector;
        this.tokenizer = SimpleTokenizer.INSTANCE;
    }

    public List<StemmedSentence> segment(String text) {
        text = text.toLowerCase();

        List<StemmedSentence> stemmedSentences = new ArrayList<StemmedSentence>();
        String[] sentences = sentenceDetector.sentDetect(text);

        for (String sentence : sentences) {
            String[] chunks = sentence.split("\\n");

            for (String chunk : chunks) {
                Matcher matcher = whitespaces.matcher(chunk);

                if (matcher.matches())
                    continue;

                Set<String> stems = applyStemming(chunk);
                stemmedSentences.add(new StemmedSentence(chunk, stems));
            }
        }

        return stemmedSentences;
    }

    private Set<String> applyStemming(String sentence) {
        Set<String> stems = new HashSet<String>();
        String[] tokens = tokenizer.tokenize(sentence);

        for (String token : tokens) {
            if (!isWord(token))
                continue;

            if (stopWordCollection.contains(token))
                continue;

            CharSequence stem = stemmer.stem(token);
            stems.add(stem.toString());
        }

        return stems;
    }

    private static boolean isNumber(String token) {
        for (Character c : token.toCharArray())
            if (!Character.isDigit(c))
                return false;
        return true;
    }

    private static boolean isWord(String token) {
        for (int i = 0; i < token.length(); i++)
            if (!Character.isLetter(token.codePointAt(i))) // works with unicode
                return false;
        return true;
    }

    public static class StemmedSentence {
        private Set<String> stems;
        private String originalText;

        public Set<String> getStems() {
            return stems;
        }

        public String getOriginalText() {
            return originalText;
        }

        private StemmedSentence(String originalText, Set<String> stems) {
            this.stems = stems;
            this.originalText = originalText;
        }
    }
}
