package it.polimi.elet.necst.heldroid.ransomware.text;

import opennlp.tools.stemmer.snowball.SnowballStemmer;

public enum SupportedLanguage {
    ENGLISH("english", "en", "eng", SnowballStemmer.ALGORITHM.ENGLISH),
    RUSSIAN("russian", "ru", "rus", SnowballStemmer.ALGORITHM.RUSSIAN),
    SPANISH("spanish", "es", "spa", SnowballStemmer.ALGORITHM.SPANISH);

    private String name, code, iso3code;
    private SnowballStemmer.ALGORITHM stemmerAlgorithm;

    public String getName() {
        return name;
    }

    public String getCode() {
        return code;
    }
    
    public String getIso3code() {
		return iso3code;
	}

    public SnowballStemmer.ALGORITHM getStemmerAlgorithm() {
        return stemmerAlgorithm;
    }

    SupportedLanguage(String name, String code, String iso3code, SnowballStemmer.ALGORITHM stemmerAlgorithm) {
        this.name = name;
        this.code = code;
        this.iso3code = iso3code;
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
