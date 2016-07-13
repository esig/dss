package eu.europa.esig.dss.utils.impl;

import java.util.Arrays;
import java.util.Collection;

import com.google.common.base.CharMatcher;
import com.google.common.base.Charsets;
import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.io.BaseEncoding;

import eu.europa.esig.dss.utils.IUtils;

public class GoogleGuavaUtils implements IUtils {

	private static final String STRING_EMPTY = "";

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
		return Strings.isNullOrEmpty(text) || CharMatcher.WHITESPACE.matchesAllOf(text);
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
		return !Strings.isNullOrEmpty(text) && CharMatcher.DIGIT.matchesAllOf(text);
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
	@SuppressWarnings("rawtypes")
	public int collectionSize(Collection collection) {
		return collection.size();
	}

	@Override
	public String toHex(byte[] bytes) {
		return BaseEncoding.base16().encode(bytes).toLowerCase();
	}

	@Override
	public String toBase64(byte[] bytes) {
		return BaseEncoding.base64().encode(bytes);
	}

	@Override
	public byte[] toBase64Binary(byte[] bytes) {
		return BaseEncoding.base64().encode(bytes).getBytes(Charsets.UTF_8);
	}

	@Override
	public byte[] fromBase64(String base64) {
		return BaseEncoding.base64().decode(base64);
	}

	@Override
	public byte[] fromBase64(byte[] base64) {
		return BaseEncoding.base64().decode(new String(base64, Charsets.UTF_8));
	}

}
