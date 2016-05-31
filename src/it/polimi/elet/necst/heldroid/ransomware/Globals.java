package it.polimi.elet.necst.heldroid.ransomware;

import java.io.File;
import java.io.FilenameFilter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import soot.dava.toolkits.base.AST.analysis.Analysis;


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
    
    public static final File getLatestAndroidVersion() {
    	final String regex = "android-(\\d{1,2})";
    	final Pattern pattern = Pattern.compile(regex);
    	
    	File[] androidPlatformFiles = ANDROID_PLATFORMS_DIRECTORY.listFiles(new FilenameFilter() {
			
			@Override
			public boolean accept(File dir, String name) {
				return name.matches(regex);
			}
		});
    	
    	int maxVersion = 0;
    	for (File androidPlaftormFile : androidPlatformFiles) {
    		Matcher matcher = pattern.matcher(androidPlaftormFile.getName());
    		if (matcher.matches()) {
    			try {
    				int version = Integer.parseInt(matcher.group(1));
    				if (version > maxVersion)
    					maxVersion = version;
    			} catch (NumberFormatException e) {
    				// Should never happen, thanks to the regex
    				e.printStackTrace();
    			}
    		}
    	}
    	
    	if (maxVersion == 0) {
    		throw new IllegalStateException("Cannot find any android version");
    	}
    	
    	File androidDir = new File(ANDROID_PLATFORMS_DIRECTORY, "android-"+maxVersion);
    	return new File(androidDir, "android.jar");
    }
}
