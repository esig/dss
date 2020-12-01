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

public final class Utils {

	public static final String EMPTY_STRING = "";

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
	}

	public static boolean isStringEmpty(String text) {
		return impl.isStringEmpty(text);
	}

	public static boolean isStringNotEmpty(String text) {
		return impl.isStringNotEmpty(text);
	}
	
	public static boolean areAllStringsEmpty(String... values) {
		for (String value : values) {
			if (isStringNotEmpty(value)) {
				return false;
			}
		}
		return true;
	}

	public static boolean isAtLeastOneStringNotEmpty(String... values) {
		return !areAllStringsEmpty(values);
	}

	public static boolean isStringBlank(String text) {
		return impl.isStringBlank(text);
	}

	public static boolean isStringNotBlank(String text) {
		return impl.isStringNotBlank(text);
	}

	public static boolean areStringsEqual(String text1, String text2) {
		return impl.areStringsEqual(text1, text2);
	}

	public static boolean areStringsEqualIgnoreCase(String text1, String text2) {
		return impl.areStringsEqualIgnoreCase(text1, text2);
	}

	public static boolean isStringDigits(String text) {
		return impl.isStringDigits(text);
	}

	public static String trim(String text) {
		return impl.trim(text);
	}

	public static String joinStrings(List<String> strings, String separator) {
		return impl.joinStrings(strings, separator);
	}

	public static String substringAfter(String text, String after) {
		return impl.substringAfter(text, after);
	}

	public static boolean endsWithIgnoreCase(String text, String expected) {
		return impl.endsWithIgnoreCase(text, expected);
	}

	public static String lowerCase(String text) {
		return impl.lowerCase(text);
	}

	public static String upperCase(String text) {
		return impl.upperCase(text);
	}

	public static boolean isArrayEmpty(Object[] array) {
		return impl.isArrayEmpty(array);
	}

	public static boolean isArrayNotEmpty(Object[] array) {
		return impl.isArrayNotEmpty(array);
	}

	public static boolean isArrayNotEmpty(byte[] array) {
		return impl.isArrayNotEmpty(array);
	}

	public static boolean isArrayEmpty(byte[] array) {
		return impl.isArrayEmpty(array);
	}

	public static byte[] subarray(byte[] array, int start, int length) {
		return impl.subarray(array, start, length);
	}

	public static boolean isTrue(Boolean bool) {
		return impl.isTrue(bool);
	}

	@SuppressWarnings("rawtypes")
	public static boolean isCollectionEmpty(Collection collection) {
		return impl.isCollectionEmpty(collection);
	}

	@SuppressWarnings("rawtypes")
	public static boolean isCollectionNotEmpty(Collection collection) {
		return impl.isCollectionNotEmpty(collection);
	}
	
	public static boolean isMapEmpty(Map<?,?> map) {
		return impl.isMapEmpty(map);
	}
	
	public static boolean isMapNotEmpty(Map<?,?> map) {
		return impl.isMapNotEmpty(map);
	}
	
	@SuppressWarnings("rawtypes")
	public static int collectionSize(Collection collection) {
		return impl.collectionSize(collection);
	}

	public static String toHex(byte[] bytes) {
		return impl.toHex(bytes);
	}

	public static byte[] fromHex(String hex) {
		return impl.fromHex(hex);
	}
	
	public static boolean isBase64Encoded(String base64String) {
		return impl.isBase64Encoded(base64String);
	}

	public static String toBase64(byte[] bytes) {
		return impl.toBase64(bytes);
	}

	public static byte[] fromBase64(String base64) {
		return impl.fromBase64(base64);
	}

	public static byte[] toByteArray(InputStream is) throws IOException {
		return impl.toByteArray(is);
	}

	public static void closeQuietly(Closeable closeable) {
		impl.closeQuietly(closeable);
	}

	public static void copy(InputStream is, OutputStream os) throws IOException {
		impl.copy(is, os);
	}

	public static void write(byte[] content, OutputStream os) throws IOException {
		impl.write(content, os);
	}
	
	public static long getInputStreamSize(InputStream is) throws IOException {
		return impl.getInputStreamSize(is);
	}

	public static void cleanDirectory(File directory) throws IOException {
		impl.cleanDirectory(directory);
	}

	public static Collection<File> listFiles(File folder, String[] extensions, boolean recursive) {
		return impl.listFiles(folder, extensions, recursive);
	}

	public static <T extends Object> List<T> reverseList(List<T> list) {
		return impl.reverseList(list);
	}

}
