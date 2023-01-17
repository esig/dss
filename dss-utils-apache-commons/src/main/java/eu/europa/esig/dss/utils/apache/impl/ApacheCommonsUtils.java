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
package eu.europa.esig.dss.utils.apache.impl;

import eu.europa.esig.dss.utils.IUtils;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;

import java.io.Closeable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Apache Commons implementation of Utils
 */
public class ApacheCommonsUtils implements IUtils {

	/**
	 * Default constructor
	 */
	public ApacheCommonsUtils() {
	}

	@Override
	public boolean isStringEmpty(String text) {
		return StringUtils.isEmpty(text);
	}

	@Override
	public boolean isStringNotEmpty(String text) {
		return StringUtils.isNotEmpty(text);
	}

	@Override
	public boolean isStringBlank(String text) {
		return StringUtils.isBlank(text);
	}

	@Override
	public boolean isStringNotBlank(String text) {
		return StringUtils.isNotBlank(text);
	}

	@Override
	public boolean areStringsEqual(String text1, String text2) {
		return StringUtils.equals(text1, text2);
	}

	@Override
	public boolean areStringsEqualIgnoreCase(String text1, String text2) {
		return StringUtils.equalsIgnoreCase(text1, text2);
	}

	@Override
	public boolean isStringDigits(String text) {
		return NumberUtils.isDigits(text);
	}

	@Override
	public String trim(String text) {
		return StringUtils.trim(text);
	}

	@Override
	public String joinStrings(Collection<String> strings, String separator) {
		return StringUtils.join(strings, separator);
	}

	@Override
	public String substringAfter(String text, String after) {
		return StringUtils.substringAfter(text, after);
	}

	@Override
	public boolean endsWithIgnoreCase(String text, String expected) {
		return StringUtils.endsWithIgnoreCase(text, expected);
	}

	@Override
	public String getFileNameExtension(String filename) {
		return FilenameUtils.getExtension(filename);
	}

	@Override
	public String lowerCase(String text) {
		return StringUtils.lowerCase(text);
	}

	@Override
	public String upperCase(String text) {
		return StringUtils.upperCase(text);
	}

	@Override
	public boolean isArrayEmpty(Object[] array) {
		return ArrayUtils.isEmpty(array);
	}

	@Override
	public boolean isArrayNotEmpty(Object[] array) {
		return ArrayUtils.isNotEmpty(array);
	}

	@Override
	public boolean isArrayEmpty(byte[] array) {
		return ArrayUtils.isEmpty(array);
	}

	@Override
	public boolean isArrayNotEmpty(byte[] array) {
		return ArrayUtils.isNotEmpty(array);
	}

	@Override
	public boolean isArrayEmpty(char[] array) {
		return ArrayUtils.isEmpty(array);
	}

	@Override
	public boolean isArrayNotEmpty(char[] array) {
		return ArrayUtils.isNotEmpty(array);
	}

	@Override
	public byte[] subarray(byte[] array, int start, int length) {
		return ArrayUtils.subarray(array, start, length);
	}

	@Override
	public boolean isTrue(Boolean bool) {
		return BooleanUtils.isTrue(bool);
	}

	@Override
	@SuppressWarnings("rawtypes")
	public boolean isCollectionEmpty(Collection collection) {
		return CollectionUtils.isEmpty(collection);
	}

	@Override
	@SuppressWarnings("rawtypes")
	public boolean isCollectionNotEmpty(Collection collection) {
		return CollectionUtils.isNotEmpty(collection);
	}

	@Override
	public boolean isMapEmpty(Map<?,?> map) {
		return MapUtils.isEmpty(map);
	}

	@Override
	public boolean isMapNotEmpty(Map<?,?> map) {
		return MapUtils.isNotEmpty(map);
	}

	@Override
	@SuppressWarnings("rawtypes")
	public int collectionSize(Collection collection) {
		return CollectionUtils.size(collection);
	}

	@Override
	public boolean isHexEncoded(String hexString) {
		Objects.requireNonNull(hexString, "String cannot be null");
		try {
			Hex.decodeHex(hexString);
			return true;
		} catch (DecoderException e) {
			return false;
		}
	}

	@Override
	public String toHex(byte[] bytes) {
		Objects.requireNonNull(bytes, "Bytes cannot be null");
		return Hex.encodeHexString(bytes);
	}

	@Override
	public byte[] fromHex(String hex) {
		Objects.requireNonNull(hex, "Hex cannot be null");
		try {
			return Hex.decodeHex(hex.toCharArray());
		} catch (DecoderException e) {
			throw new IllegalArgumentException("Unable to extract binary from Hex", e);
		}
	}
	
	@Override
	public boolean isBase64Encoded(String base64String) {
		return Base64.isBase64(base64String);
	}

	@Override
	public String toBase64(byte[] bytes) {
		return Base64.encodeBase64String(bytes);
	}

	@Override
	public byte[] fromBase64(String base64) {
		return Base64.decodeBase64(base64);
	}

	@Override
	public byte[] toByteArray(InputStream is) throws IOException {
		return IOUtils.toByteArray(is);
	}

	@Override
	public void closeQuietly(Closeable closeable) {
		try {
            if (closeable != null) {
                closeable.close();
            }
        } catch (final IOException e) {
            // ignore
        }
	}

	@Override
	public void copy(InputStream is, OutputStream os) throws IOException {
		IOUtils.copy(is, os);
	}

	@Override
	public void write(byte[] content, OutputStream os) throws IOException {
		IOUtils.write(content, os);
	}
	
	@Override
	public long getInputStreamSize(InputStream is) throws IOException {
		long byteCounter = 0;
		int nRead;
	    byte[] data = new byte[8192];
	    while ((nRead = IOUtils.read(is, data)) > 0) {
	    	byteCounter += nRead;
	    }
		return byteCounter;
	}

	@Override
	public boolean compareInputStreams(InputStream stream1, InputStream stream2) throws IOException {
		return IOUtils.contentEquals(stream1, stream2);
	}

	@Override
	public void cleanDirectory(File directory) throws IOException {
		try {
			FileUtils.cleanDirectory(directory);
		} catch (IllegalArgumentException e) {
			// Apache throws IllegalArgumentException
			throw new FileNotFoundException(e.getMessage());
		}
	}

	@Override
	public Collection<File> listFiles(File folder, String[] extensions, boolean recursive) {
		return FileUtils.listFiles(folder, extensions, recursive);
	}

	@Override
	public <T> List<T> reverseList(List<T> list) {
		List<T> reverse = new ArrayList<>(list);
		Collections.reverse(reverse);
		return reverse;
	}

	@Override
	public <T> boolean containsAny(Collection<T> superCollection, Collection<T> subCollection) {
		return CollectionUtils.containsAny(superCollection, subCollection);
	}

}
