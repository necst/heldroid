package it.polimi.elet.necst.heldroid.ransomware.images;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import javax.imageio.ImageIO;

import org.languagetool.Language;
import org.languagetool.Languages;
import org.languagetool.MultiThreadedJLanguageTool;
import org.languagetool.language.AmericanEnglish;
import org.languagetool.rules.Rule;
import org.languagetool.rules.spelling.SpellingCheckRule;
import org.languagetool.tools.Tools;

import it.polimi.elet.necst.heldroid.ransomware.text.SupportedLanguage;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassification;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassifier;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassifierCollection;
import it.polimi.elet.necst.heldroid.ransomware.text.scanning.ResourceScanner;
import it.polimi.elet.necst.heldroid.utils.FileSystem;
import net.sourceforge.tess4j.Tesseract;
import net.sourceforge.tess4j.TesseractException;

public class ImageScanner extends ResourceScanner {

	// Min number of characters that text must contain to be analysed
	private static final int MIN_TEXT_LENGTH = 15;

	public ImageScanner(TextClassifierCollection textClassifierCollection) {
		super(textClassifierCollection);
	}

	@Override
	protected TextClassification findRansomwareText() {
		TextClassification finalClassification = TextClassification.empty();

		FilenameFilter filter = new FilenameFilter() {

			@Override
			public boolean accept(File dir, String name) {
				// Android drawable resources can be jpg, png or gif files
				final String[] extensions = new String[] { ".jpg", ".png",
						".gif" };

				for (String ext : extensions) {
					if (name.endsWith(ext))
						return true;
				}
				return false;
			}
		};

		// Search all images inside res and assets folders
		File resFolder = new File(this.unpackedApkDirectory, "res");
		File assetsFolder = new File(this.unpackedApkDirectory, "assets");
		List<File> filesToScan = new LinkedList<>();

		if (resFolder.exists()) {
			filesToScan.addAll(
					FileSystem.listFilesRecursively(resFolder, filter));
		}
		if (assetsFolder.exists()) {
			filesToScan.addAll(
					FileSystem.listFilesRecursively(assetsFolder, filter));
		}

		// Analyze files
		for (File file : filesToScan) {
			TextClassification partial = this.findRansomwareText(file);
			finalClassification.append(partial);
		}

		return finalClassification;
	}

	private TextClassification findRansomwareText(File image) {
		try {
			File imageBW = convertToGrayscale(image);

			String extracted = extractText(imageBW);

			// Remove unnecessary file
			imageBW.delete();

			if (extracted != null) {
				TextClassification result = this.classifyElementText(extracted,
						TextClassification.empty());
				extractLikelihood(image, result);
				result.setFileClassification(getFileClassification());
				return result;
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Throwable e) {
			e.printStackTrace();
		}
		return TextClassification.empty();
	}

	protected TextClassification classifyElementText(String text,
			TextClassification totalClassification) {
		if (isSuitableForClassification(text)) {
			TextClassifier textClassifier = this.getTextClassifierFor(text);

			if (textClassifier != null) {
				TextClassification textClassification = textClassifier.classify(
						text);
				totalClassification.append(textClassification);
			}
		}

		return totalClassification;
	}

	private String extractText(File image) {
		// Use tesseract
		String extracted = tesseract(image);

		if (extracted	.trim()
						.length() >= MIN_TEXT_LENGTH) {
			// Detect language
			SupportedLanguage lang = languageOf(extracted);

			if (lang != null) {
				// Apply text corrector
				return correct(extracted, lang);
			}
		}
		return null;
	}

	/**
	 * Tries to correct the text by applying the rules related to the supplied
	 * language.
	 * 
	 * @param text
	 *            The text to correct
	 * @param lang
	 *            The language of {@code text}
	 * @return The corrected text
	 * @throws IllegalArgumentException
	 *             If the language is not supported or unrecognized
	 */
	private String correct(String extracted, SupportedLanguage lang)
			throws IllegalArgumentException {
		Language language = null;

		/*
		 * Create the language automatically from language code. The only
		 * exception is english language, since we need to know the country
		 * variant of the language (e.g. en-US).
		 */
		if (lang == SupportedLanguage.ENGLISH) {
			// By default we'll use american english for english lang
			language = new AmericanEnglish();
		} else {
			language = Languages.getLanguageForShortName(lang.getCode());
		}

		// Main class of the corrector. Uses as much threads as CPU cores
		// available
		MultiThreadedJLanguageTool lt = new MultiThreadedJLanguageTool(language,
				Runtime	.getRuntime()
						.availableProcessors());

		// Disable useless rules
		lt.disableRule("WHITESPACE_RULE");

		// Words whitelist
		List<String> wordsToIgnore = Arrays.asList("moneypak", "greendot");
		for (Rule rule : lt.getAllActiveRules()) {
			if (rule instanceof SpellingCheckRule) {
				((SpellingCheckRule) rule).addIgnoreTokens(wordsToIgnore);
			}
		}

		// JLanguageTool expects the Unicode text to be in NFKC form
		extracted = Normalizer.normalize(extracted, Normalizer.Form.NFKC);

		try {
			String corrected = Tools.correctText(extracted, lt);
			return corrected;
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	private String tesseract(File image) {
		Tesseract instance = Tesseract.getInstance();
		instance.setDatapath("/usr/local/share/tessdata/");
		instance.setLanguage("eng+rus");

		// Ignore the following chars: | (pipe), \ (backslash)
		instance.setTessVariable("tessedit_char_blacklist", "|\\");
		try {
			String result = instance.doOCR(image);
			return result;
		} catch (TesseractException e) {
			e.printStackTrace();
		}

		return null;
	}

	private File convertToGrayscale(File image) throws IOException {
		// Open the original image
		BufferedImage bi = ImageIO.read(image);
		int width, height;

		width = bi.getWidth();
		height = bi.getHeight();

		// Transform each pixel's color
		for (int i = 0; i < height; i++) {
			for (int j = 0; j < width; j++) {
				Color c = new Color(bi.getRGB(j, i));
				int red = (int) (c.getRed() * 0.299);
				int green = (int) (c.getGreen() * 0.587);
				int blue = (int) (c.getBlue() * 0.114);
				int sum = red + green + blue;
				int threshold = 256 / 2;

				/*
				 * If it is a dark color, transform it to black, otherwise leave
				 * it as it is
				 */
				if (sum < threshold) {
					sum = 0;
				}

				Color newColor = new Color(sum, sum, sum);
				// Change image color
				bi.setRGB(j, i, newColor.getRGB());
			}
		}

		// Create temp "black/white" image, it will be deleted after analysis
		File output = File.createTempFile("gray", ".png");
		ImageIO.write(bi, "png", output);
		return output;
	}
}
