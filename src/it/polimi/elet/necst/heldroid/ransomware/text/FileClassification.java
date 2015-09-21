package it.polimi.elet.necst.heldroid.ransomware.text;

import java.io.File;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * This class lets you track all files containing strings belonging to one of the categories listed in {@link FileClassification#CATEGORIES} 
 * @author Nicola
 *
 */
public class FileClassification {

	public static final String[] CATEGORIES = new String[] { "threat", "porn", 
			"law", "copyright", "moneypak" };

	private Map<String, List<String>> classifiedFiles;
	
	public FileClassification() {
		classifiedFiles = new HashMap<>();
		
		// initialize empty categories
		for (String cat : CATEGORIES) {
			classifiedFiles.put(cat, new LinkedList<>());
		}
	}
	
	/**
	 * Adds a file to a category
	 * @param category The category to which the file belongs
	 * @param file The file thats belong to a category
	 */
	public void addFile(String category, File file) {
		this.addFile(category, file.getAbsolutePath());
	}
	
	/**
	 * Clears all previously added files 
	 */
	public void clear() {
		for (String cat : CATEGORIES) {
			// If the list does not exist, this method creates it
			if (classifiedFiles.get(cat) != null)
				classifiedFiles.get(cat).clear();
			else
				classifiedFiles.put(cat, new LinkedList<>());
		}
	}
	
	/**
	 * This method lets you merge two {@link FileClassification} instances: <code>this</code> and <code>other</code>
	 * @param other The instance with which this instance should be merged
	 */
	public void merge(FileClassification other) {
		for (String category : CATEGORIES) {
			List<String> thisList = classifiedFiles.get(category);
			
			// The list should already exists, but let's check it anyway
			if (thisList == null) {
				thisList = new LinkedList<>();
				classifiedFiles.put(category, thisList);
			}
			
			int previousSize = thisList.size();
			
			List<String> otherList = other.getClassifiedFiles().get(category);
			
			if (otherList != null) {
				thisList.addAll(otherList);
			}
			assert thisList.size() == previousSize + (otherList != null ? otherList.size() : 0);
		}
		
	}
	
	public void addFile(String category, String fileName) {
		
		List<String> list = classifiedFiles.get(category);
		
		if (list == null) {
			list = new LinkedList<>();
			classifiedFiles.put(category, list);
		}
		
		System.out.println("ADDING FILE "+fileName);

		// add file only if it's not already included in the list
		if (!list.contains(fileName)) {
			list.add(fileName);
		}
		
		System.out.println("List size = "+list.size());
	}
	
	public Map<String, List<String>> getClassifiedFiles() {
		return classifiedFiles;
	}
	
	@Override
	public String toString() {
//		StringBuilder builder = new StringBuilder("[");
//		
//		for (String cat : CATEGORIES) {
//			builder.append(cat);
//			builder.append(": ");
//			builder.append(getClassifiedFiles().get(cat));
//			
//			if (!cat.equals(CATEGORIES[CATEGORIES.length-1]))
//				builder.append(", ");
//		}
//		
//		builder.append("]");
//		return builder.toString();
		return classifiedFiles.toString();
	}

}
