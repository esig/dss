/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.utils;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * Contains common utils
 */
public final class Utils {

	/** The empty string */
	public static final String EMPTY_STRING = "";

	/** The implementation to be used */
	private static IUtils impl;

	static {
		ServiceLoader<IUtils> loader = ServiceLoader.load(IUtils.class);
		Iterator<IUtils> iterator = loader.iterator();
		if (!iterator.hasNext()) {
			throw new ExceptionInInitializerError(
					"No implementation found for IUtils in classpath, please choose between dss-utils-apache-commons or dss-utils-google-guava");
		}
		impl = iterator.next();
	}

	private Utils() {
		// empty
	}

	/**
	 * Checks if the string is empty
	 * Ex. "nowina" = false; "" = true
	 *
	 * NOTE: blank string (e.g. "   ") is not empty!
	 *
	 * @param text {@link String}
	 * @return TRUE if the string is empty, FALSE otherwise
	 */
	public static boolean isStringEmpty(String text) {
		return impl.isStringEmpty(text);
	}

	/**
	 * Checks if the string is not blank
	 * Ex. "nowina" = true; "   " = false
	 *
	 * @param text {@link String}
	 * @return TRUE if the string is not blank, FALSE otherwise
	 */
	public static boolean isStringNotEmpty(String text) {
		return impl.isStringNotEmpty(text);
	}

	/**
	 * Checks if all strings are empty
	 *
	 * @param values {@link String}s to check
	 * @return TRUE if all strings are empty, FALSE otherwise
	 */
	public static boolean areAllStringsEmpty(String... values) {
		for (String value : values) {
			if (isStringNotEmpty(value)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Checks if at least one string is not empty
	 *
	 * @param values {@link String}s to check
	 * @return TRUE if at least one string is not empty, FALSE otherwise
	 */
	public static boolean isAtLeastOneStringNotEmpty(String... values) {
		return !areAllStringsEmpty(values);
	}

	/**
	 * Checks if the string is blank
	 * Ex. "nowina" = false; "   " = true
	 *
	 * @param text {@link String}
	 * @return TRUE if the string is blank, FALSE otherwise
	 */
	public static boolean isStringBlank(String text) {
		return impl.isStringBlank(text);
	}

	/**
	 * Checks if the string is not blank
	 * Ex. "nowina" = true; "   " = false
	 *
	 * @param text {@link String}
	 * @return TRUE if the string is not blank, FALSE otherwise
	 */
	public static boolean isStringNotBlank(String text) {
		return impl.isStringNotBlank(text);
	}

	/**
	 * Checks if the strings are equal
	 * Ex. "nowina" == "nowina" = true; "nowina" == "Nowina" = false
	 *
	 * @param text1 {@link String}
	 * @param text2 {@link String}
	 * @return TRUE if the strings are equal, FALSE otherwise
	 */
	public static boolean areStringsEqual(String text1, String text2) {
		return impl.areStringsEqual(text1, text2);
	}

	/**
	 * Checks if the strings are equal with case ignore
	 * Ex. "nowina" == "Nowina" = true; "water" == "fire" = false
	 *
	 * @param text1 {@link String}
	 * @param text2 {@link String}
	 * @return TRUE if the strings are equal with case ignore, FALSE otherwise
	 */
	public static boolean areStringsEqualIgnoreCase(String text1, String text2) {
		return impl.areStringsEqualIgnoreCase(text1, text2);
	}

	/**
	 * Checks if the string contains only digits
	 * Ex. "123" = true; "1a2b" = false
	 *
	 * @param text {@link String}
	 * @return TRUE if the string contains only digits, FALSE otherwise
	 */
	public static boolean isStringDigits(String text) {
		return impl.isStringDigits(text);
	}

	/**
	 * Trims the string, by removing all leading and descending spaces and lines
	 * Ex. "   123 " = "123"
	 *
	 * @param text {@link String}
	 * @return the trimmed string
	 */
	public static String trim(String text) {
		return impl.trim(text);
	}

	/**
	 * Joins the strings with the given separator
	 * Ex. "Nowina" "123", "," = "Nowina,123"
	 *
	 * @param strings a collection of {@link String}s
	 * @param separator {@link String}
	 * @return the joined string
	 */
	public static String joinStrings(List<String> strings, String separator) {
		return impl.joinStrings(strings, separator);
	}

	/**
	 * Returns a substring after the specified character
	 * Ex. "aaaaa?bbb", "?" = "bbb"
	 *
	 * @param text {@link String} to get a substring from
	 * @param after {@link String} string to get a substring after which
	 * @return the substring
	 */
	public static String substringAfter(String text, String after) {
		return impl.substringAfter(text, after);
	}

	/**
	 * Checks if the string ends with case ignore
	 * Ex. "hello", "LO" = true; "hello", "a" = false
	 *
	 * @param text {@link String} to check
	 * @param expected {@link String} the end string to check
	 * @return TRUE if the string ends with case ignore, FALSE otherwise
	 */
	public static boolean endsWithIgnoreCase(String text, String expected) {
		return impl.endsWithIgnoreCase(text, expected);
	}

	/**
	 * This method returns an extension for the given filename
	 * Ex. "file.xml" = "xml"; "document.pdf" = "pdf"
	 *
	 * @param filename {@link String} representing a filename extracted from a file
	 * @return {@link String} extension
	 */
	public static String getFileNameExtension(String filename) {
		return impl.getFileNameExtension(filename);
	}

	/**
	 * Converts a string to its lower case representation
	 * Ex. "Nowina" = "nowina"
	 *
	 * @param text {@link String}
	 * @return the lower case string
	 */
	public static String lowerCase(String text) {
		return impl.lowerCase(text);
	}

	/**
	 * Converts a string to its upper case representation
	 * Ex. "Nowina" = "NOWINA"
	 *
	 * @param text {@link String}
	 * @return the upper case string
	 */
	public static String upperCase(String text) {
		return impl.upperCase(text);
	}

	/**
	 * Checks if the array is null or empty
	 *
	 * @param array to check
	 * @return TRUE if the array is null or empty, FALSE otherwise
	 */
	public static boolean isArrayEmpty(Object[] array) {
		return impl.isArrayEmpty(array);
	}

	/**
	 * Checks if the array is not null nor empty
	 *
	 * @param array to check
	 * @return TRUE if the array is not null nor empty, FALSE otherwise
	 */
	public static boolean isArrayNotEmpty(Object[] array) {
		return impl.isArrayNotEmpty(array);
	}

	/**
	 * Checks if the byte array is null or empty
	 *
	 * @param array byte array to check
	 * @return TRUE if the byte array is null or empty, FALSE otherwise
	 */
	public static boolean isArrayEmpty(byte[] array) {
		return impl.isArrayEmpty(array);
	}

	/**
	 * Checks if the byte array is not null nor empty
	 *
	 * @param array byte array to check
	 * @return TRUE if the byte array is not null nor empty, FALSE otherwise
	 */
	public static boolean isArrayNotEmpty(byte[] array) {
		return impl.isArrayNotEmpty(array);
	}

	/**
	 * Returns a subArray, starting from position {@code start} with the defined length {@code length}
	 *
	 * @param array byte array to get subArray from
	 * @param start the start index of the subArray
	 * @param length the length of the subArray
	 * @return subArray
	 */
	public static byte[] subarray(byte[] array, int start, int length) {
		return impl.subarray(array, start, length);
	}

	/**
	 * Checks if the Boolean value is set to true
	 *
	 * NOTE: if null, returns false!
	 *
	 * @param bool {@link Boolean}
	 * @return TRUE if the value is set to true, FALSE otherwise
	 */
	public static boolean isTrue(Boolean bool) {
		return impl.isTrue(bool);
	}

	/**
	 * Checks if the collection is null or empty
	 *
	 * @param collection to check
	 * @return TRUE if the collection is null or empty, FALSE otherwise
	 */
	@SuppressWarnings("rawtypes")
	public static boolean isCollectionEmpty(Collection collection) {
		return impl.isCollectionEmpty(collection);
	}

	/**
	 * Checks if the collection is not null nor empty
	 *
	 * @param collection to check
	 * @return TRUE if the collection is not null nor empty, FALSE otherwise
	 */
	@SuppressWarnings("rawtypes")
	public static boolean isCollectionNotEmpty(Collection collection) {
		return impl.isCollectionNotEmpty(collection);
	}

	/**
	 * Checks if the map is null or empty
	 *
	 * @param map to check
	 * @return TRUE if the map is null or empty, FALSE otherwise
	 */
	public static boolean isMapEmpty(Map<?,?> map) {
		return impl.isMapEmpty(map);
	}

	/**
	 * Checks if the map is not null nor empty
	 *
	 * @param map to check
	 * @return TRUE if the map is not null nor empty, FALSE otherwise
	 */
	public static boolean isMapNotEmpty(Map<?,?> map) {
		return impl.isMapNotEmpty(map);
	}

	/**
	 * Gets the size of the collection
	 *
	 * @param collection {@link Collection}
	 * @return size of the collection
	 */
	@SuppressWarnings("rawtypes")
	public static int collectionSize(Collection collection) {
		return impl.collectionSize(collection);
	}

	/**
	 * Checks if the string is HEX (base16) encoded
	 *
	 * @param hexString {@link String}
	 * @return TRUE if he string is HEX encoded, FALSE otherwise
	 */
	public static boolean isHexEncoded(String hexString) {
		return impl.isHexEncoded(hexString);
	}

	/**
	 * Transforms the binaries to String HEX representation
	 *
	 * @param bytes byte array
	 * @return {@link String} HEX-encoded
	 */
	public static String toHex(byte[] bytes) {
		return impl.toHex(bytes);
	}

	/**
	 * Transforms a HEX-encoded string to byte array
	 *
	 * @param hex {@link String} hex-encoded
	 * @return byte array
	 */
	public static byte[] fromHex(String hex) {
		return impl.fromHex(hex);
	}

	/**
	 * Checks if the string is base64-encoded
	 *
	 * @param base64String {@link String}
	 * @return TRUE if the string is base64-encoded, FALSE otherwise
	 */
	public static boolean isBase64Encoded(String base64String) {
		return impl.isBase64Encoded(base64String);
	}

	/**
	 * Transforms the binaries to String base64-encoded representation
	 *
	 * @param bytes byte array
	 * @return {@link String} base64-encoded
	 */
	public static String toBase64(byte[] bytes) {
		return impl.toBase64(bytes);
	}

	/**
	 * Transforms a base64-encoded string to byte array
	 *
	 * @param base64 {@link String} base64-encoded
	 * @return byte array
	 */
	public static byte[] fromBase64(String base64) {
		return impl.fromBase64(base64);
	}

	/**
	 * Reads the InputStream and returns the resulting byte array
	 *
	 * @param is {@link InputStream}
	 * @return byte array
	 * @throws IOException if an exception occurs
	 */
	public static byte[] toByteArray(InputStream is) throws IOException {
		return impl.toByteArray(is);
	}

	/**
	 * Closes quietly
	 *
	 * @param closeable {@link Closeable}
	 */
	public static void closeQuietly(Closeable closeable) {
		impl.closeQuietly(closeable);
	}

	/**
	 * Copies {@code is} to {@code os}
	 *
	 * @param is {@link InputStream} to copy
	 * @param os {@link OutputStream} to write the value into
	 * @throws IOException if an exception occurs
	 */
	public static void copy(InputStream is, OutputStream os) throws IOException {
		impl.copy(is, os);
	}

	/**
	 * Writes {@code content} to {@code os}
	 *
	 * @param content byte array to write
	 * @param os {@link OutputStream} to write the value into
	 * @throws IOException if an exception occurs
	 */
	public static void write(byte[] content, OutputStream os) throws IOException {
		impl.write(content, os);
	}

	/**
	 * Gets the size of the InputStream content
	 *
	 * @param is {@link InputStream}
	 * @return size
	 * @throws IOException if an exception occurs
	 */
	public static long getInputStreamSize(InputStream is) throws IOException {
		return impl.getInputStreamSize(is);
	}

	/**
	 * Cleans the directory
	 *
	 * @param directory {@link File}
	 * @throws IOException if an exception occurs
	 */
	public static void cleanDirectory(File directory) throws IOException {
		impl.cleanDirectory(directory);
	}

	/**
	 * Lists all files from the {@code folder} with the given {@code extensions}
	 *
	 * @param folder {@link File} the directory to get files from
	 * @param extensions {@link String}s to get files with
	 * @param recursive defines if the files has to be obtained recursively (from children directories)
	 * @return a collection of {@link File}s
	 */
	public static Collection<File> listFiles(File folder, String[] extensions, boolean recursive) {
		return impl.listFiles(folder, extensions, recursive);
	}

	/**
	 * Creates a reversed copy of the list
	 *
	 * @param list {@link List} to get a reversed copy of
	 * @param <T> the class of list elements
	 * @return reversed list
	 */
	public static <T> List<T> reverseList(List<T> list) {
		return impl.reverseList(list);
	}

	/**
	 * This method returns boolean result whether the {@code superCollection}
	 * contains any element of the {@code subCollection}
	 *
	 * Ex. {'A', 'B', 'C'}, {'B', 'C', 'D'} = TRUE
	 *
	 * @param superCollection first collection
	 * @param subCollection second collection
	 * @param <T> object
	 * @return TRUE if both collection intersect each other, FALSE otherwise
	 */
	public static <T> boolean containsAny(Collection<T> superCollection, Collection<T> subCollection) {
		return impl.containsAny(superCollection, subCollection);
	}

}
