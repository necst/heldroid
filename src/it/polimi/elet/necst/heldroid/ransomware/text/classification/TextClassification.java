package it.polimi.elet.necst.heldroid.ransomware.text.classification;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import it.polimi.elet.necst.heldroid.ransomware.text.FileClassification;

public class TextClassification {
	private List<SentenceClassification> sentenceClassifications;

	private FileClassification fileClassification;

	public FileClassification getFileClassification() {
		return fileClassification;
	}

	public void setFileClassification(FileClassification fileClassification) {
		this.fileClassification = fileClassification;
	}

	public List<SentenceClassification> getSentenceClassifications() {
		return sentenceClassifications;
	}

	TextClassification(List<SentenceClassification> sentenceClassifications) {
		this.sentenceClassifications = sentenceClassifications;
		this.fileClassification = new FileClassification();
	}

	public double maxLikelihood(String category) {
		double max = 0;

		for (SentenceClassification c : sentenceClassifications)
			if (c.getCategory().equals(category) && c.getLikelihood() > max)
				max = c.getLikelihood();

		return max;
	}

	public SentenceClassification containsAnySentence(double minLikelihood,
			String... categories) {
		List<String> categoryList = Arrays.asList(categories);

		for (SentenceClassification c : sentenceClassifications)
			if (categoryList.contains(c.getCategory())
					&& c.getLikelihood() >= minLikelihood)
				return c;

		return null;
	}

	public List<SentenceClassification> containsAllSentences(
			double minLikelihood, String... categories) {
		List<SentenceClassification> list = new ArrayList<SentenceClassification>(
				categories.length);
		Map<String, Boolean> found = new HashMap<String, Boolean>();
		int foundCount = 0;

		for (SentenceClassification c : sentenceClassifications)
			if ((!found.containsKey(c.getCategory())
					|| !found.get(c.getCategory()))
					&& c.getLikelihood() >= minLikelihood) {
				found.put(c.getCategory(), true);
				list.add(c);
				foundCount++;

				if (foundCount == categories.length)
					return list;
			}

		return new ArrayList<SentenceClassification>();
	}

	public List<SentenceClassification> findAllSentences(double minLikelihood,
			String... categories) {
		List<SentenceClassification> list = new ArrayList<SentenceClassification>();
		List<String> categoryList = Arrays.asList(categories);

		for (SentenceClassification c : sentenceClassifications)
			if (categoryList.contains(c.getCategory())
					&& c.getLikelihood() >= minLikelihood)
				list.add(c);

		return list;
	}

	public void append(TextClassification other) {
		sentenceClassifications.addAll(other.sentenceClassifications);
		
		// Merge also FileClassification data
		this.fileClassification.merge(other.getFileClassification());
	}

	public static TextClassification empty() {
		return new TextClassification(new ArrayList<SentenceClassification>());
	}
}
