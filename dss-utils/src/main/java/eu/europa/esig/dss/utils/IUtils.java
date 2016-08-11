package eu.europa.esig.dss.utils;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;

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

	@SuppressWarnings("rawtypes")
	int collectionSize(Collection collection);

	String toHex(byte[] bytes);

	String toBase64(byte[] bytes);

	byte[] fromBase64(String base64);

	byte[] toByteArray(InputStream is) throws IOException;

	void closeQuietly(Closeable closeable);

	void copy(InputStream is, OutputStream os) throws IOException;

	void write(byte[] content, OutputStream os) throws IOException;

	void cleanDirectory(File directory) throws IOException;

	Collection<File> listFiles(File folder, String[] extensions, boolean recursive);

}
