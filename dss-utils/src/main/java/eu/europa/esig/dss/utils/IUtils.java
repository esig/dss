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
import java.util.List;
import java.util.Map;

/**
 * The interface contains the common methods to be used within the DSS core
 *
 */
public interface IUtils {

	/**
	 * Checks if the string is empty
	 * Ex. "nowina" = false; "" = true
	 *
	 * NOTE: blank string (e.g. "   ") is not empty!
	 *
	 * @param text {@link String}
	 * @return TRUE if the string is empty, FALSE otherwise
	 */
	boolean isStringEmpty(String text);

	/**
	 * Checks if the string is not empty
	 * Ex. "nowina" = true; "" = false
	 *
	 * NOTE: blank string (e.g. "   ") is not empty!
	 *
	 * @param text {@link String}
	 * @return TRUE if the string is not empty, FALSE otherwise
	 */
	boolean isStringNotEmpty(String text);

	/**
	 * Checks if the string is blank
	 * Ex. "nowina" = false; "   " = true
	 *
	 * @param text {@link String}
	 * @return TRUE if the string is blank, FALSE otherwise
	 */
	boolean isStringBlank(String text);

	/**
	 * Checks if the string is not blank
	 * Ex. "nowina" = true; "   " = false
	 *
	 * @param text {@link String}
	 * @return TRUE if the string is not blank, FALSE otherwise
	 */
	boolean isStringNotBlank(String text);

	/**
	 * Checks if the strings are equal
	 * Ex. "nowina" == "nowina" = true; "nowina" == "Nowina" = false
	 *
	 * @param text1 {@link String}
	 * @param text2 {@link String}
	 * @return TRUE if the strings are equal, FALSE otherwise
	 */
	boolean areStringsEqual(String text1, String text2);

	/**
	 * Checks if the strings are equal with case ignore
	 * Ex. "nowina" == "Nowina" = true; "water" == "fire" = false
	 *
	 * @param text1 {@link String}
	 * @param text2 {@link String}
	 * @return TRUE if the strings are equal with case ignore, FALSE otherwise
	 */
	boolean areStringsEqualIgnoreCase(String text1, String text2);

	/**
	 * Checks if the string contains only digits
	 * Ex. "123" = true; "1a2b" = false
	 *
	 * @param text {@link String}
	 * @return TRUE if the string contains only digits, FALSE otherwise
	 */
	boolean isStringDigits(String text);

	/**
	 * Trims the string, by removing all leading and descending spaces and lines
	 * Ex. "   123 " = "123"
	 *
	 * @param text {@link String}
	 * @return the trimmed string
	 */
	String trim(String text);

	/**
	 * Joins the strings with the given separator
	 * Ex. "Nowina" "123", "," = "Nowina,123"
	 *
	 * @param strings a collection of {@link String}s
	 * @param separator {@link String}
	 * @return the joined string
	 */
	String joinStrings(Collection<String> strings, String separator);

	/**
	 * Returns a substring after the specified character
	 * Ex. "aaaaa?bbb", "?" = "bbb"
	 *
	 * @param text {@link String} to get a substring from
	 * @param after {@link String} string to get a substring after which
	 * @return the substring
	 */
	String substringAfter(String text, String after);

	/**
	 * Checks if the string ends with case ignore
	 * Ex. "hello", "LO" = true; "hello", "a" = false
	 *
	 * @param text {@link String} to check
	 * @param expected {@link String} the end string to check
	 * @return TRUE if the string ends with case ignore, FALSE otherwise
	 */
	boolean endsWithIgnoreCase(String text, String expected);

	/**
	 * This method returns an extension for the given filename
	 * Ex. "file.xml" = "xml"; "document.pdf" = "pdf"
	 *
	 * @param filename {@link String} representing a filename extracted from a file
	 * @return {@link String} extension
	 */
	String getFileNameExtension(String filename);

	/**
	 * Converts a string to its lower case representation
	 * Ex. "Nowina" = "nowina"
	 *
	 * @param text {@link String}
	 * @return the lower case string
	 */
	String lowerCase(String text);

	/**
	 * Converts a string to its upper case representation
	 * Ex. "Nowina" = "NOWINA"
	 *
	 * @param text {@link String}
	 * @return the upper case string
	 */
	String upperCase(String text);

	/**
	 * Checks if the array is null or empty
	 *
	 * @param array to check
	 * @return TRUE if the array is null or empty, FALSE otherwise
	 */
	boolean isArrayEmpty(Object[] array);

	/**
	 * Checks if the array is not null nor empty
	 *
	 * @param array to check
	 * @return TRUE if the array is not null nor empty, FALSE otherwise
	 */
	boolean isArrayNotEmpty(Object[] array);

	/**
	 * Checks if the byte array is null or empty
	 *
	 * @param array byte array to check
	 * @return TRUE if the byte array is null or empty, FALSE otherwise
	 */
	boolean isArrayEmpty(byte[] array);

	/**
	 * Checks if the byte array is not null nor empty
	 *
	 * @param array byte array to check
	 * @return TRUE if the byte array is not null nor empty, FALSE otherwise
	 */
	boolean isArrayNotEmpty(byte[] array);

	/**
	 * Checks if the char array is null or empty
	 *
	 * @param array char array to check
	 * @return TRUE if the char array is null or empty, FALSE otherwise
	 */
	boolean isArrayEmpty(char[] array);

	/**
	 * Checks if the char array is not null nor empty
	 *
	 * @param array char array to check
	 * @return TRUE if the char array is not null nor empty, FALSE otherwise
	 */
	boolean isArrayNotEmpty(char[] array);

	/**
	 * Returns a subArray, starting from position {@code start} with the defined length {@code length}
	 *
	 * @param array byte array to get subArray from
	 * @param start the start index of the subArray
	 * @param length the length of the subArray
	 * @return subArray
	 */
	byte[] subarray(byte[] array, int start, int length);

	/**
	 * Checks if the Boolean value is set to true
	 *
	 * NOTE: if null, returns false!
	 *
	 * @param bool {@link Boolean}
	 * @return TRUE if the value is set to true, FALSE otherwise
	 */
	boolean isTrue(Boolean bool);

	/**
	 * Checks if the collection is null or empty
	 *
	 * @param collection to check
	 * @return TRUE if the collection is null or empty, FALSE otherwise
	 */
	@SuppressWarnings("rawtypes")
	boolean isCollectionEmpty(Collection collection);

	/**
	 * Checks if the collection is not null nor empty
	 *
	 * @param collection to check
	 * @return TRUE if the collection is not null nor empty, FALSE otherwise
	 */
	@SuppressWarnings("rawtypes")
	boolean isCollectionNotEmpty(Collection collection);

	/**
	 * Checks if the map is null or empty
	 *
	 * @param map to check
	 * @return TRUE if the map is null or empty, FALSE otherwise
	 */
	boolean isMapEmpty(Map<?,?> map);

	/**
	 * Checks if the map is not null nor empty
	 *
	 * @param map to check
	 * @return TRUE if the map is not null nor empty, FALSE otherwise
	 */
	boolean isMapNotEmpty(Map<?,?> map);

	/**
	 * Gets the size of the collection
	 *
	 * @param collection {@link Collection}
	 * @return size of the collection
	 */
	@SuppressWarnings("rawtypes")
	int collectionSize(Collection collection);

	/**
	 * Checks if the string is HEX (base16) encoded
	 *
	 * @param hexString {@link String}
	 * @return TRUE if he string is HEX encoded, FALSE otherwise
	 */
	boolean isHexEncoded(String hexString);

	/**
	 * Transforms the binaries to String HEX representation
	 *
	 * @param bytes byte array
	 * @return {@link String} HEX-encoded
	 */
	String toHex(byte[] bytes);

	/**
	 * Transforms a HEX-encoded string to byte array
	 *
	 * @param hex {@link String} hex-encoded
	 * @return byte array
	 */
	byte[] fromHex(String hex);

	/**
	 * Checks if the string is base64-encoded
	 *
	 * @param base64String {@link String}
	 * @return TRUE if he string is base64-encoded, FALSE otherwise
	 */
	boolean isBase64Encoded(String base64String);

	/**
	 * Transforms the binaries to String base64-encoded representation
	 *
	 * @param bytes byte array
	 * @return {@link String} base64-encoded
	 */
	String toBase64(byte[] bytes);

	/**
	 * Transforms a base64-encoded string to byte array
	 *
	 * @param base64 {@link String} base64-encoded
	 * @return byte array
	 */
	byte[] fromBase64(String base64);

	/**
	 * Reads the InputStream and returns the resulting byte array
	 *
	 * @param is {@link InputStream}
	 * @return byte array
	 * @throws IOException if an exception occurs
	 */
	byte[] toByteArray(InputStream is) throws IOException;

	/**
	 * Closes quietly
	 *
	 * @param closeable {@link Closeable}
	 */
	void closeQuietly(Closeable closeable);

	/**
	 * Copies {@code is} to {@code os}
	 *
	 * @param is {@link InputStream} to copy
	 * @param os {@link OutputStream} to write the value into
	 * @throws IOException if an exception occurs
	 */
	void copy(InputStream is, OutputStream os) throws IOException;

	/**
	 * Writes {@code content} to {@code os}
	 *
	 * @param content byte array to write
	 * @param os {@link OutputStream} to write the value into
	 * @throws IOException if an exception occurs
	 */
	void write(byte[] content, OutputStream os) throws IOException;

	/**
	 * Gets the size of the InputStream content
	 *
	 * @param is {@link InputStream}
	 * @return size
	 * @throws IOException if an exception occurs
	 */
	long getInputStreamSize(InputStream is) throws IOException;

	/**
	 * Cleans the directory
	 *
	 * @param directory {@link File}
	 * @throws IOException if an exception occurs
	 */
	void cleanDirectory(File directory) throws IOException;

	/**
	 * Lists all files from the {@code folder} with the given {@code extensions}
	 *
	 * @param folder {@link File} the directory to get files from
	 * @param extensions {@link String}s to get files with
	 * @param recursive defines if the files has to be obtained recursively (from children directories)
	 * @return a collection of {@link File}s
	 */
	Collection<File> listFiles(File folder, String[] extensions, boolean recursive);

	/**
	 * Creates a reversed copy of the list
	 *
	 * @param list {@link List} to get a reversed copy of
	 * @param <T> the class of list elements
	 * @return reversed list
	 */
	<T> List<T> reverseList(List<T> list);

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
	<T> boolean containsAny(Collection<T> superCollection, Collection<T> subCollection);

}
