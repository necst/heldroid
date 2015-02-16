package it.polimi.elet.necst.heldroid.ransomware.text.classification;

import it.polimi.elet.necst.heldroid.ransomware.text.SupportedLanguage;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class TextClassifierCollection {
    private Map<SupportedLanguage, TextClassifier> classifiers;

    public Set<SupportedLanguage> getSupposedLanguages() {
        return classifiers.keySet();
    }

    public TextClassifierCollection() {
        this.classifiers = new HashMap<SupportedLanguage, TextClassifier>();
    }

    public void add(SupportedLanguage language, TextClassifier classifier) {
        this.classifiers.put(language, classifier);
    }

    public TextClassifier get(SupportedLanguage language) {
        return this.classifiers.get(language);
    }
}
