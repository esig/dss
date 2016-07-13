package eu.europa.esig.dss.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.utils.impl.UtilsBinder;

public final class Utils {

	private static final Logger logger = LoggerFactory.getLogger(Utils.class);

	public static final String EMPTY_STRING = "";

	private static final String STATIC_UTILS_BINDER_PATH = "eu/europa/esig/dss/utils/impl/UtilsBinder.class";

	private static UtilsStatus status = UtilsStatus.NOT_INITIALIZED;

	private static IUtils impl;

	static {
		if (UtilsStatus.NOT_INITIALIZED == status) {
			performInitialization();
		}
	}

	private Utils() {
	}

	private static void performInitialization() {
		Set<URL> utilsImplementationPathSet = findPossibleUtilsImplementations();
		if (utilsImplementationPathSet == null || utilsImplementationPathSet.size() == 0) {
			throw new RuntimeException("No implementation found in the classpath");
		} else if (utilsImplementationPathSet.size() > 1) {
			throw new RuntimeException("More than one implementation found in the classpath");
		}
		impl = UtilsBinder.getSingleton().getUtilsFactory().getUtils();
		status = UtilsStatus.INITIALIZED;
	}

	private static Set<URL> findPossibleUtilsImplementations() {
		Set<URL> utilsImplementationPathSet = new LinkedHashSet<URL>();
		try {
			ClassLoader utilsClassLoader = Utils.class.getClassLoader();
			Enumeration<URL> paths;
			if (utilsClassLoader == null) {
				paths = ClassLoader.getSystemResources(STATIC_UTILS_BINDER_PATH);
			} else {
				paths = utilsClassLoader.getResources(STATIC_UTILS_BINDER_PATH);
			}
			while (paths.hasMoreElements()) {
				URL path = paths.nextElement();
				utilsImplementationPathSet.add(path);
			}
		} catch (IOException e) {
			logger.error("Cannot retrieve classloader : " + e.getMessage(), e);
		}
		return utilsImplementationPathSet;
	}

	public static boolean isStringEmpty(String text) {
		return impl.isStringEmpty(text);
	}

	public static boolean isStringNotEmpty(String text) {
		return impl.isStringNotEmpty(text);
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

	@SuppressWarnings("rawtypes")
	public static int collectionSize(Collection collection) {
		return impl.collectionSize(collection);
	}

	public static String toHex(byte[] bytes) {
		return impl.toHex(bytes);
	}

	public static String toBase64(byte[] bytes) {
		return impl.toBase64(bytes);
	}

	public static byte[] toBase64Binary(byte[] bytes) {
		return impl.toBase64Binary(bytes);
	}

	public static byte[] fromBase64(String base64) {
		return impl.fromBase64(base64);
	}

	public static byte[] fromBase64(byte[] base64Bytes) {
		return impl.fromBase64(base64Bytes);
	}

	public static byte[] toByteArray(InputStream is) throws IOException {
		return impl.toByteArray(is);
	}

	public static void closeQuietly(InputStream is) {
		impl.closeQuietly(is);
	}

	public static void closeQuietly(OutputStream os) {
		impl.closeQuietly(os);
	}

}
