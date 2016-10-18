package it.polimi.elet.necst.heldroid.ransomware.images;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.imageio.ImageIO;

import org.languagetool.Language;
import org.languagetool.Languages;
import org.languagetool.MultiThreadedJLanguageTool;
import org.languagetool.language.AmericanEnglish;
import org.languagetool.rules.Rule;
import org.languagetool.rules.spelling.SpellingCheckRule;
import org.languagetool.tools.Tools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.polimi.elet.necst.heldroid.ransomware.text.SupportedLanguage;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassification;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassifier;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassifierCollection;
import it.polimi.elet.necst.heldroid.ransomware.text.scanning.ResourceScanner;
import it.polimi.elet.necst.heldroid.utils.FileSystem;

public class ImageScanner extends ResourceScanner {
  private static final Logger logger = LoggerFactory.getLogger(ImageScanner.class);

	// Min number of characters that text must contain to be analysed
	private static final int MIN_TEXT_LENGTH = 15;
	private static final String TESSERACT_DEFAULT_LANG = "eng+rus";

	/*
	 * The biggest Android icon usually measures 200x200 px.
	 */
	private static final int MIN_IMAGE_HEIGHT = 201; // Pixels
	private static final int MIN_IMAGE_WIDTH = 201; // Pixels

	private String tesseractLanguage = TESSERACT_DEFAULT_LANG;

	public ImageScanner(TextClassifierCollection textClassifierCollection) {
		super(textClassifierCollection);

    logger.info("Creating ImageScanner");
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
					/*
					 * Icons starting with "abc_" belongs to android appcompat
					 * v7
					 */
					if (!name.startsWith("abc_") && name.endsWith(ext))
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
			/*
			 * We will discard small images, since they can be icons and we
			 * don't want to waste time
			 */
			if (!shouldAnalyze(image)) {
				System.out.println("Skipping small image: " + image.getName());
				return TextClassification.empty();
			}

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
			System.err.println(
					"Cannot convert image to grayscale: " + e.getMessage());
		}
		return TextClassification.empty();
	}

	private boolean shouldAnalyze(File image) {
		try {
			BufferedImage bi = ImageIO.read(image);
			return bi != null &&
					bi.getWidth() >= MIN_IMAGE_WIDTH &&
					bi.getHeight() >= MIN_IMAGE_HEIGHT;
		} catch (IOException e) {
			// If we cannot open the image we cannot analyze it
			System.err.println("Cannot open image: " + image.getName());
			return false;
		}
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

	/**
	 * Instructs Tesseract to recognize character based on the specified
	 * language(s). If {@code hint} is {@code null}, a default language of
	 * "eng+rus" will be used.
	 * 
	 * @param hint
	 *            The languages Tesseract should use.
	 */
	public void setTesseractLanguage(Set<SupportedLanguage> hint) {
		if (hint == null || hint.size() == 0) {
			// This will set the default value for tesseract
			this.tesseractLanguage = TESSERACT_DEFAULT_LANG;
			return;
		}

		Iterator<SupportedLanguage> iterator = hint.iterator();

		// Join all hints with a "plus" sign
		StringBuilder builder = new StringBuilder();
		while (iterator.hasNext()) {
			builder.append(iterator	.next()
									.getIso3code());
			builder.append('+');
		}
		// Remove trailing "plus"
		builder.setLength(builder.length() - 1);

		this.tesseractLanguage = builder.toString();
	}

	private String tesseract(File image) {
		if (tesseractLanguage == null) {
			tesseractLanguage = TESSERACT_DEFAULT_LANG;
		}

		BufferedReader reader = null;
		File extractedTextFile = null;
		try {
			extractedTextFile = File.createTempFile("extracted", ".txt");
			String extractedTextWithoutExtension = extractedTextFile.getAbsolutePath()
																	.substring(
																			0,
																			extractedTextFile	.getAbsolutePath()
																								.lastIndexOf(
																										'.'));
			Process tesseract = Runtime	.getRuntime()
										.exec(new String[] { "tesseract",
												image.getAbsolutePath(),
												extractedTextWithoutExtension,
												"-l", tesseractLanguage, "-c",
												"tessedit_char_blacklist=|\\" });
			tesseract.waitFor();

			reader = new BufferedReader(new FileReader(extractedTextFile));
			StringBuilder result = new StringBuilder();

			String line;
			while ((line = reader.readLine()) != null) {
				result.append(line);
			}
			return result.toString();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		} finally {
			if (extractedTextFile != null) {
				extractedTextFile.delete();
			}
			if (reader != null) {
				try {
					reader.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		// instance.setDatapath("/usr/local/share/tessdata/");

		// instance.setLanguage(tesseractLanguage);

		// Ignore the following chars: | (pipe), \ (backslash)
		// instance.setTessVariable("tessedit_char_blacklist", "|\\");
		// try {
		// String result = instance.doOCR(image);
		// return result;
		// } catch (TesseractException e) {
		// e.printStackTrace();
		// }

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
