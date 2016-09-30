package it.polimi.elet.necst.heldroid.ransomware;

import java.io.File;

public class Globals {
    public static final File MODELS_DIRECTORY = new File("models");
    public static final File STOP_WORDS_DIRECTORY = new File("stop-words");
    public static final File LANGUAGE_PROFILES_DIRECTORY = new File("language-profiles");
    public static final File ANDROID_PLATFORMS_DIRECTORY = new File("android-platforms");
    public static final File TRAINING_DATA_DIRECTORY = new File("training");

    public static final File EXAMINED_FILES_LIST_FILE = new File("examined.txt");
    public static final File PERFORMANCE_FILE = new File("diagnostics.csv");

    public static final double MIN_LIKELIHOOD_THRESHOLD = 0.35;
    public static final double MAX_LIKELIHOOD_THRESHOLD = 0.63;
    public static final int MIN_PRODUCED_STEMS = 3;
    public static final int MAX_PRODUCED_STEMS = 6;
}
