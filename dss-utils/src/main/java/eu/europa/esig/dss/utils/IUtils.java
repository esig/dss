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

public interface IUtils {

	boolean isStringEmpty(String text);

	boolean isStringNotEmpty(String text);

	boolean isStringBlank(String text);

	boolean isStringNotBlank(String text);

	boolean areStringsEqual(String text1, String text2);

	boolean areStringsEqualIgnoreCase(String text1, String text2);

	boolean isStringDigits(String text);

	String trim(String text);

	String joinStrings(Collection<String> strings, String separator);

	String substringAfter(String text, String after);

	boolean endsWithIgnoreCase(String text, String expected);

	String lowerCase(String text);

	String upperCase(String text);

	boolean isArrayEmpty(Object[] array);

	boolean isArrayNotEmpty(Object[] array);

	boolean isArrayNotEmpty(byte[] array);

	boolean isArrayEmpty(byte[] array);

	byte[] subarray(byte[] array, int start, int length);

	boolean isTrue(Boolean bool);

	@SuppressWarnings("rawtypes")
	boolean isCollectionEmpty(Collection collection);

	@SuppressWarnings("rawtypes")
	boolean isCollectionNotEmpty(Collection collection);
	
	boolean isMapEmpty(Map<?,?> map);
	
	boolean isMapNotEmpty(Map<?,?> map);

	@SuppressWarnings("rawtypes")
	int collectionSize(Collection collection);

	String toHex(byte[] bytes);

	byte[] fromHex(String hex);
	
	boolean isBase64Encoded(String base64String);

	String toBase64(byte[] bytes);

	byte[] fromBase64(String base64);

	byte[] toByteArray(InputStream is) throws IOException;

	void closeQuietly(Closeable closeable);

	void copy(InputStream is, OutputStream os) throws IOException;

	void write(byte[] content, OutputStream os) throws IOException;
	
	long getInputStreamSize(InputStream is) throws IOException;

	void cleanDirectory(File directory) throws IOException;

	Collection<File> listFiles(File folder, String[] extensions, boolean recursive);

	<T extends Object> List<T> reverseList(List<T> list);

}
