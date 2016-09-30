package it.polimi.elet.necst.heldroid.utils;

import java.util.Collection;

import org.json.JSONArray;

public class CollectionToJsonConverter {

	/**
	 * This method will create a JSONArray from a {@link Collection}. For each
	 * object inside the collection, the {@link Object#toString()} method is
	 * called and added to the JSONArray.
	 * 
	 * @param collection
	 *            The collection to transform to a JSONArray.
	 * @return An empty JSONArray if the collection is either {@code null} or
	 *         empty, otherwise a JSONArray containing the
	 *         {@link Object#toString()} representation of each object inside
	 *         the collection.
	 */
	public static JSONArray convert(Collection<?> collection) {
		JSONArray result = new JSONArray();

		if (collection != null && collection.size() > 0) {
			for (Object element : collection) {
				result.put(element.toString());
			}
		}

		return result;
	}
}
