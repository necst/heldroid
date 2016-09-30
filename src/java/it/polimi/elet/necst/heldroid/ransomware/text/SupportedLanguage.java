package it.polimi.elet.necst.heldroid.ransomware.text;

import opennlp.tools.stemmer.snowball.SnowballStemmer;

public enum SupportedLanguage {
    ENGLISH("english", "en", SnowballStemmer.ALGORITHM.ENGLISH),
    RUSSIAN("russian", "ru", SnowballStemmer.ALGORITHM.RUSSIAN),
    SPANISH("spanish", "es", SnowballStemmer.ALGORITHM.SPANISH);

    private String name, code;
    private SnowballStemmer.ALGORITHM stemmerAlgorithm;

    public String getName() {
        return name;
    }

    public String getCode() {
        return code;
    }

    public SnowballStemmer.ALGORITHM getStemmerAlgorithm() {
        return stemmerAlgorithm;
    }

    SupportedLanguage(String name, String code, SnowballStemmer.ALGORITHM stemmerAlgorithm) {
        this.name = name;
        this.code = code;
        this.stemmerAlgorithm = stemmerAlgorithm;
    }

    public static SupportedLanguage fromCode(String languageCode) {
        languageCode = languageCode.toLowerCase();

        for (SupportedLanguage language : SupportedLanguage.values())
            if (language.getCode().equals(languageCode))
                return language;

        return null;
    }
}
