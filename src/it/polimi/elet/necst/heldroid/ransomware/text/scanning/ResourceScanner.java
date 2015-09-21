package it.polimi.elet.necst.heldroid.ransomware.text.scanning;

import com.cybozu.labs.langdetect.Detector;
import com.cybozu.labs.langdetect.DetectorFactory;
import com.cybozu.labs.langdetect.LangDetectException;

import it.polimi.elet.necst.heldroid.ransomware.text.FileClassification;
import it.polimi.elet.necst.heldroid.ransomware.text.SupportedLanguage;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassification;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassifier;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassifierCollection;

import java.io.File;
import java.io.FilenameFilter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class ResourceScanner {
	private static final Pattern RES_VALUE_PATTERN = Pattern.compile(
			"\\@\\w+\\/[\\w_]+");
	private static final int MIN_STRING_LENGTH = 30;

	protected TextClassifierCollection textClassifierCollection;
	protected File unpackedApkDirectory;
	protected AcceptanceStrategy acceptanceStrategy;
	protected TextClassification textClassification;
	
	protected FileClassification fileClassification = new FileClassification();

	private Set<String> encounteredLanguages;
	private int totalSentences;

	protected File getApkResourceDirectory() {
		return new File(unpackedApkDirectory, "res");
	}

	protected List<File> getApkResourceDirectories(final String prefix) {
		File res = this.getApkResourceDirectory();
		List<File> result = new ArrayList<File>();

		File[] matchedFiles = res.listFiles(new FilenameFilter() {
			@Override
			public boolean accept(File dir, String name) {
				return name.toLowerCase().startsWith(prefix.toLowerCase());
			}
		});

		if (matchedFiles != null) {
			for (File file : matchedFiles)
				if (file.isDirectory())
					result.add(file);
		}

		return result;
	}

	public void setUnpackedApkDirectory(File unpackedApkDirectory) {
		this.unpackedApkDirectory = unpackedApkDirectory;
	}

	public void setAcceptanceStrategy(AcceptanceStrategy acceptanceStrategy) {
		this.acceptanceStrategy = acceptanceStrategy;
	}
	
	public FileClassification getFileClassification() {
		return fileClassification;
	}

	public void extractLikelihood(String fileName,
			TextClassification classification) {

		if (fileName == null) {
			throw new IllegalArgumentException("File shouldn't be null");
		}

		if (classification == null) {
			throw new IllegalArgumentException(
					"Classification shouldn't be null");
		}
		
		for (String category : FileClassification.CATEGORIES) {
			double score = classification.maxLikelihood(category);
			if (score > 0d) {
				fileClassification.addFile(category, fileName);
			}
		}
	}

	public void extractLikelihood(File file,
			TextClassification classification) {
		if (file == null) {
			throw new IllegalArgumentException("File shouldn't be null");
		}

		this.extractLikelihood(file.getAbsolutePath(), classification);
	}

	public ResourceScanner(TextClassifierCollection textClassifierCollection) {
		this.textClassifierCollection = textClassifierCollection;
		this.resetStatistics();
	}

	public AcceptanceStrategy.Result evaluate() {
		if (unpackedApkDirectory == null || !unpackedApkDirectory.exists())
			throw new NullPointerException("UnpackedApkDirectory not set!");

		if (acceptanceStrategy == null)
			throw new NullPointerException("AcceptanceStrategy not set!");

		this.resetStatistics();

		this.textClassification = this.findRansomwareText();

		return acceptanceStrategy.accepts(this.textClassification);
	}

	protected abstract TextClassification findRansomwareText();

	private void resetStatistics() {
		this.encounteredLanguages = new HashSet<String>();
		this.totalSentences = 0;
	}

	protected SupportedLanguage languageOf(String text) {
		try {
			Detector detector = DetectorFactory.create();
			detector.append(text);
			String languageCode = detector.detect();
			return SupportedLanguage.fromCode(languageCode);
		} catch (LangDetectException e) {
			return null;
		}
	}

	protected boolean isSuitableForClassification(String text) {
		if ((text == null) || (text.length() < MIN_STRING_LENGTH))
			return false;

		Matcher matcher = RES_VALUE_PATTERN.matcher(text);

		return !matcher.matches();
	}

	protected TextClassifier getTextClassifierFor(String text) {
		SupportedLanguage language = languageOf(text);

		if (language == null)
			return null;

		this.totalSentences++;
		this.encounteredLanguages.add(language.getName());

		return textClassifierCollection.get(language);
	}

	public String getScanReport() {
		StringBuilder builder = new StringBuilder();

		if (this.encounteredLanguages.size() > 0) {
			builder.append("Languages: ");
			for (String lang : this.encounteredLanguages)
				builder.append(lang.toUpperCase() + ", ");
		}

		builder.append("Analyzed sentences: ");
		builder.append(String.format("%d", this.totalSentences));

		return builder.toString();
	}
}
