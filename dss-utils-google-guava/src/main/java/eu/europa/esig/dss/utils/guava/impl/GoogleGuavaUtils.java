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
package eu.europa.esig.dss.utils.guava.impl;

import com.google.common.base.Ascii;
import com.google.common.base.CharMatcher;
import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteStreams;
import com.google.common.io.Closeables;
import com.google.common.io.Files;
import com.google.common.primitives.Bytes;
import eu.europa.esig.dss.utils.IUtils;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Google Guava implementation of Utils
 */
public class GoogleGuavaUtils implements IUtils {

	/** Defined an empty String */
	private static final String STRING_EMPTY = "";

	/**
	 * Default constructor
	 */
	public GoogleGuavaUtils() {
		// empty
	}

	@Override
	public boolean isStringEmpty(String text) {
		return Strings.isNullOrEmpty(text);
	}

	@Override
	public boolean isStringNotEmpty(String text) {
		return !Strings.isNullOrEmpty(text);
	}

	@Override
	public boolean isStringBlank(String text) {
		return Strings.isNullOrEmpty(text) || CharMatcher.whitespace().matchesAllOf(text);
	}

	@Override
	public boolean isStringNotBlank(String text) {
		return !isStringBlank(text);
	}

	@Override
	public boolean areStringsEqual(String text1, String text2) {
		if (text1 == null && text2 == null) {
			return true;
		} else if (text1 == null || text2 == null) {
			return false;
		}
		return text1.equals(text2);
	}

	@Override
	public boolean areStringsEqualIgnoreCase(String text1, String text2) {
		if (text1 == null && text2 == null) {
			return true;
		} else if (text1 == null || text2 == null) {
			return false;
		}
		return text1.equalsIgnoreCase(text2);
	}

	@Override
	public boolean isStringDigits(String text) {
		return !Strings.isNullOrEmpty(text) && CharMatcher.inRange('0', '9').matchesAllOf(text);
	}

	@Override
	public String trim(String text) {
		if (Strings.isNullOrEmpty(text)) {
			return text;
		}
		return text.trim();
	}

	@Override
	public String joinStrings(Collection<String> strings, String separator) {
		if (strings == null) {
			return null;
		}
		if (Strings.isNullOrEmpty(separator)) {
			separator = STRING_EMPTY;
		}
		Joiner joiner = Joiner.on(separator);
		return joiner.join(strings);
	}

	@Override
	public byte[] concat(byte[]... byteArrays) {
		return Bytes.concat(byteArrays);
	}

	@Override
	public String substringAfter(String text, String after) {
		if (Strings.isNullOrEmpty(text)) {
			return text;
		}
		if (after == null) {
			return STRING_EMPTY;
		}
		int indexOf = text.indexOf(after);
		if (indexOf == -1) {
			return STRING_EMPTY;
		}
		return text.substring(indexOf + after.length());
	}

	@Override
	public boolean endsWithIgnoreCase(String text, String expected) {
		if (Strings.isNullOrEmpty(text) || Strings.isNullOrEmpty(expected)) {
			return false;
		}
		return lowerCase(text).endsWith(lowerCase(expected));
	}

	@Override
	public String getFileNameExtension(String filename) {
		if (filename != null) {
			return Files.getFileExtension(filename);
		}
		return null;
	}

	@Override
	public String lowerCase(String text) {
		if (Strings.isNullOrEmpty(text)) {
			return text;
		}
		return text.toLowerCase();
	}

	@Override
	public String upperCase(String text) {
		if (Strings.isNullOrEmpty(text)) {
			return text;
		}
		return text.toUpperCase();
	}

	@Override
	public boolean isArrayEmpty(Object[] array) {
		return array == null || array.length == 0;
	}

	@Override
	public boolean isArrayNotEmpty(Object[] array) {
		return !isArrayEmpty(array);
	}

	@Override
	public boolean isArrayEmpty(byte[] array) {
		return array == null || array.length == 0;
	}

	@Override
	public boolean isArrayNotEmpty(byte[] array) {
		return !isArrayEmpty(array);
	}

	@Override
	public boolean isArrayEmpty(char[] array) {
		return array == null || array.length == 0;
	}

	@Override
	public boolean isArrayNotEmpty(char[] array) {
		return !isArrayEmpty(array);
	}

	@Override
	public byte[] subarray(byte[] array, int start, int length) {
		if (array == null) {
			return null;
		}
		return Arrays.copyOfRange(array, start, length);
	}

	@Override
	public boolean isTrue(Boolean bool) {
		return bool != null && bool;
	}

	@Override
	@SuppressWarnings("rawtypes")
	public boolean isCollectionEmpty(Collection collection) {
		return collection == null || collection.isEmpty();
	}

	@Override
	@SuppressWarnings("rawtypes")
	public boolean isCollectionNotEmpty(Collection collection) {
		return collection != null && !collection.isEmpty();
	}

	@Override
	public boolean isMapEmpty(Map<?,?> map) {
		return map == null || map.isEmpty();
	}

	@Override
	public boolean isMapNotEmpty(Map<?,?> map) {
		return map != null && !map.isEmpty();
	}

	@Override
	@SuppressWarnings("rawtypes")
	public int collectionSize(Collection collection) {
		if (collection == null) {
			return 0;
		}
		return collection.size();
	}

	@Override
	public boolean isHexEncoded(String hexString) {
		Objects.requireNonNull(hexString, "String cannot be null");
		return BaseEncoding.base16().lowerCase().canDecode(Ascii.toLowerCase(hexString));
	}

	@Override
	public String toHex(byte[] bytes) {
		Objects.requireNonNull(bytes, "Bytes cannot be null");
		return BaseEncoding.base16().encode(bytes).toLowerCase();
	}

	@Override
	public byte[] fromHex(String hex) {
		Objects.requireNonNull(hex, "Hex cannot be null");
		return BaseEncoding.base16().lowerCase().decode(Ascii.toLowerCase(hex));
	}
	
	@Override
	public boolean isBase64Encoded(String base64String) {
		return BaseEncoding.base64().canDecode(CharMatcher.whitespace().removeFrom(base64String));
	}

	@Override
	public String toBase64(byte[] bytes) {
		return BaseEncoding.base64().encode(bytes);
	}

	@Override
	public byte[] fromBase64(String base64) {
		return BaseEncoding.base64().decode(CharMatcher.whitespace().removeFrom(base64));
	}

	@Override
	public byte[] toByteArray(InputStream is) throws IOException {
		return ByteStreams.toByteArray(is);
	}

	@Override
	public void closeQuietly(Closeable closeable) {
		try {
			Closeables.close(closeable, true);
		} catch (IOException e) {
			/* never happen */
		}
	}

	@Override
	public void copy(InputStream is, OutputStream os) throws IOException {
		ByteStreams.copy(is, os);
	}

	@Override
	public void write(byte[] content, OutputStream os) throws IOException {
		ByteStreams.copy(new ByteArrayInputStream(content), os);
	}
	
	@Override
	public long getInputStreamSize(InputStream is) throws IOException {
		return ByteStreams.exhaust(is);
	}

	@Override
	public boolean compareInputStreams(InputStream stream1, InputStream stream2) throws IOException {
		if (stream1 == stream2) {
			return true;
		}
		if (stream1 == null || stream2 == null) {
			return false;
		}
		if (!(stream1 instanceof BufferedInputStream)) {
			stream1 = new BufferedInputStream(stream1);
		}
		if (!(stream2 instanceof BufferedInputStream)) {
			stream2 = new BufferedInputStream(stream2);
		}
		int b1 = stream1.read();
		while (-1 != b1) {
			int b2 = stream2.read();
			if (b1 != b2) {
				return false;
			}
			b1 = stream1.read();
		}
		int b2 = stream2.read();
		return b2 == -1;
	}

	@Override
	public void cleanDirectory(File directory) throws IOException {
		Objects.requireNonNull(directory, "Directory cannot be null");
		if (!directory.exists() || !directory.isDirectory()) {
			throw new FileNotFoundException(String.format("Directory with name '%s' not found", directory.getName()));
		} else if (directory.isDirectory()) {
			File[] listFiles = directory.listFiles();
			if (listFiles != null) {
				for (File file : listFiles) {
					if (file.isDirectory()) {
						cleanDirectory(file);
					} else if (file.isFile()) {
						if (!file.delete()) {
							throw new IOException(String.format("Unable to delete file with name '%s'", file.getName()));
						}
					}
				}
			}
		}
	}

	@Override
	public Collection<File> listFiles(File folder, String[] extensions, boolean recursive) {
		return Lists.newArrayList(Iterables.filter(Files.fileTraverser().depthFirstPostOrder(folder), new FilterByExtensions(extensions)));
	}

	@Override
	public <T> List<T> reverseList(List<T> list) {
		return Lists.reverse(new ArrayList<>(list));
	}

	@Override
	public <T> boolean containsAny(Collection<T> superCollection, Collection<T> subCollection) {
		return !Collections.disjoint(superCollection, subCollection);
	}

}
