package eu.europa.esig.dss.utils.impl;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;

import eu.europa.esig.dss.utils.IUtils;

public class ApacheCommonsUtils implements IUtils {

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
	public boolean isArrayNotEmpty(byte[] array) {
		return ArrayUtils.isNotEmpty(array);
	}

	@Override
	public boolean isArrayEmpty(byte[] array) {
		return ArrayUtils.isEmpty(array);
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
	@SuppressWarnings("rawtypes")
	public int collectionSize(Collection collection) {
		return CollectionUtils.size(collection);
	}

	@Override
	public String toHex(byte[] bytes) {
		return Hex.encodeHexString(bytes);
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
		IOUtils.closeQuietly(closeable);
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
	public void cleanDirectory(File directory) throws IOException {
		FileUtils.cleanDirectory(directory);
	}

	@Override
	public Collection<File> listFiles(File folder, String[] extensions, boolean recursive) {
		return FileUtils.listFiles(folder, extensions, recursive);
	}

}
