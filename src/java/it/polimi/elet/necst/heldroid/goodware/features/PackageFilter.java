package it.polimi.elet.necst.heldroid.goodware.features;

import it.polimi.elet.necst.heldroid.goodware.features.core.FeatureGatherer;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;
import it.polimi.elet.necst.heldroid.smali.SmaliLoader;
import it.polimi.elet.necst.heldroid.smali.core.SmaliClass;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.*;

public class PackageFilter extends FeatureGatherer {
  private ApplicationData currentData;

  @Override
  public OperationMode getOperationMode() {
    return OperationMode.DATA_INSPECTION;
  }

  @Override
  public boolean extractFeatures(ApplicationData applicationData) {
    super.resetFeaturesValues();

    this.currentData = applicationData;

    boolean result = this.checkMainPackageName();
    this.checkMetrics();

    return result;
  }

  private boolean checkMainPackageName() {
    if (!super.isAnyFeatureEnabled(FEATURE_SHORT_NAME, FEATURE_DOMAIN, FEATURE_TETRAGRAM))
      return false;

    if (validDomains == null)
      loadValidDomains();

    String packageName = currentData.getManifestReport().getPackageName();
    String[] packageParts = packageName.split("\\.");

    boolean shortName = (packageParts.length <= 1);
    boolean validDomain = (validDomains.contains(packageParts[0].toUpperCase()));
    boolean tetragrams = false;

    for (String part : packageParts)
      if (containsConsonantNGram(part, 4)) {
        tetragrams = true;
        break;
      }

    super.setFeatureValue(0, shortName);
    super.setFeatureValue(1, validDomain);
    super.setFeatureValue(2, tetragrams);

    return shortName || !validDomain || tetragrams;
  }

  private void checkMetrics() {
    if (!super.isAnyFeatureEnabled(FEATURE_AVG_CLASS_SIZE, FEATURE_CLASS_COUNT, FEATURE_CLASS_COUNT_IN_MAIN_PACKAGE,
        FEATURE_MAIN_PACKAGE_OBFUSCATED, FEATURE_OBFUSCATION, FEATURE_PACKAGE_COUNT))
      return;

    String mainPackageName = currentData.getManifestReport().getPackageName().replace(".", "/"); // in
                                                    // smali
                                                    // format
    SmaliLoader loader = currentData.getSmaliLoader();
    Set<String> packages = new HashSet<String>();

    boolean obfuscated = false;
    boolean mainPackageObfuscated = false;
    double totalClassSize = 0;
    int classCountInMainPackage = 0;
    int classCount = 0;

    for (SmaliClass klass : loader.getClasses()) {
      String packageName = klass.getName().getPackageName();
      String className = klass.getName().getSimpleName();
      boolean inMainPackage = packageName.startsWith(mainPackageName);

      packages.add(packageName);

      classCount++;
      totalClassSize += klass.getSize();

      if (inMainPackage)
        classCountInMainPackage++;

      if (className.length() == 1 && Character.isLowerCase(className.charAt(0))) {
        obfuscated = true;

        if (inMainPackage)
          mainPackageObfuscated = true;
      }
    }

    super.setFeatureValue(3, packages.size());
    super.setFeatureValue(4, classCount);
    super.setFeatureValue(5, classCountInMainPackage);
    super.setFeatureValue(6, totalClassSize / classCount);
    super.setFeatureValue(7, obfuscated);
    super.setFeatureValue(8, mainPackageObfuscated);
  }

  @Override
  protected void defineFeatures() {
    super.addFeature(FEATURE_SHORT_NAME);
    super.addFeature(FEATURE_DOMAIN);
    super.addFeature(FEATURE_TETRAGRAM);

    super.addFeature(FEATURE_PACKAGE_COUNT);
    super.addFeature(FEATURE_CLASS_COUNT);
    super.addFeature(FEATURE_CLASS_COUNT_IN_MAIN_PACKAGE);
    super.addFeature(FEATURE_AVG_CLASS_SIZE);

    super.addFeature(FEATURE_OBFUSCATION);
    super.addFeature(FEATURE_MAIN_PACKAGE_OBFUSCATED);
  }

  private static boolean containsConsonantNGram(String text, int n) {
    int counter = 0;

    for (Character c : text.toCharArray()) {
      if (Character.isLetter(c) && !VOWELS.contains(Character.toLowerCase(c)))
        counter++;
      else
        counter = 0;

      if (counter >= n)
        return true;
    }

    return false;
  }

  private static synchronized void loadValidDomains() {
    InputStream stream = PackageFilter.class.getResourceAsStream(VALID_DOMAIN_LIST_NAME);
    Reader reader = new InputStreamReader(stream);
    BufferedReader textReader = new BufferedReader(reader);
    String line;

    validDomains = new ArrayList<String>();

    try {
      while ((line = textReader.readLine()) != null)
        validDomains.add(line);

      textReader.close();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  private static final String FEATURE_SHORT_NAME = "Single Package Name";
  private static final String FEATURE_DOMAIN = "Valid Domain in Package Name";
  private static final String FEATURE_TETRAGRAM = "Package Name contains Tetragrams";
  private static final String FEATURE_PACKAGE_COUNT = "Total number of packages";
  private static final String FEATURE_CLASS_COUNT = "Total number of classes";
  private static final String FEATURE_CLASS_COUNT_IN_MAIN_PACKAGE = "Number of classes in main package";
  private static final String FEATURE_AVG_CLASS_SIZE = "Average class size";
  private static final String FEATURE_OBFUSCATION = "Obsfuscation present";
  private static final String FEATURE_MAIN_PACKAGE_OBFUSCATED = "Is main package obfuscated?";

  private static final String VALID_DOMAIN_LIST_NAME = "domain-list.txt";
  private static final List<Character> VOWELS = Arrays.asList('a', 'e', 'i', 'o', 'u', 'y');
  private static List<String> validDomains;
}
