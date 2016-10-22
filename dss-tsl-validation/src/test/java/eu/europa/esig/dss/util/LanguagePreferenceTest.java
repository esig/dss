package eu.europa.esig.dss.util;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.Collections;

import org.junit.Test;

public class LanguagePreferenceTest {

	protected final MockLanguageDependentString s1Eng = new MockLanguageDependentString("a string", "en");
	protected final MockLanguageDependentString s2Eng = new MockLanguageDependentString("another string", "en");
	protected final MockLanguageDependentString s3Eng = new MockLanguageDependentString("yet another string", "en");

	protected final MockLanguageDependentString s1Ger = new MockLanguageDependentString("eine Zeichenkette", "de");
	protected final MockLanguageDependentString s2Ger = new MockLanguageDependentString("eine andere Zeichenkette",
			"de");
	protected final MockLanguageDependentString s3Ger = new MockLanguageDependentString("eine noch andere Zeichenkette",
			"de");

	@Test
	public void testEmptyPreference() {
		final LanguagePreference p = new LanguagePreference();
		assertNull(p.getPreferredOrFirst(null));
		assertNull(p.getPreferredOrFirst(Collections.emptyList()));
		assertSame(s1Eng, p.getPreferredOrFirst(Arrays.asList(s1Eng)));
		assertSame(s1Eng, p.getPreferredOrFirst(Arrays.asList(s1Eng, s2Ger)));
		assertSame(s1Eng, p.getPreferredOrFirst(Arrays.asList(s1Eng, s2Eng)));
		assertSame(s2Ger, p.getPreferredOrFirst(Arrays.asList(s2Ger, s2Eng)));
	}

	@Test
	public void testEnglishPreference() {
		final LanguagePreference p = new LanguagePreference("en");
		assertNull(p.getPreferredOrFirst(null));
		assertNull(p.getPreferredOrFirst(Collections.emptyList()));
		assertSame(s1Eng, p.getPreferredOrFirst(Arrays.asList(s1Eng)));
		assertSame(s1Eng, p.getPreferredOrFirst(Arrays.asList(s1Eng, s2Ger)));
		assertSame(s1Eng, p.getPreferredOrFirst(Arrays.asList(s1Eng, s2Eng)));
		assertSame(s3Eng, p.getPreferredOrFirst(Arrays.asList(s2Ger, s3Eng)));
		assertSame(s2Ger, p.getPreferredOrFirst(Arrays.asList(s2Ger, s1Ger)));
	}

	@Test
	public void testGermanPreference() {
		final LanguagePreference p = new LanguagePreference("de");
		assertNull(p.getPreferredOrFirst(null));
		assertNull(p.getPreferredOrFirst(Collections.emptyList()));
		assertSame(s1Eng, p.getPreferredOrFirst(Arrays.asList(s1Eng)));
		assertSame(s2Ger, p.getPreferredOrFirst(Arrays.asList(s1Eng, s2Ger)));
		assertSame(s1Eng, p.getPreferredOrFirst(Arrays.asList(s1Eng, s2Eng)));
		assertSame(s2Ger, p.getPreferredOrFirst(Arrays.asList(s2Ger, s3Eng)));
		assertSame(s2Ger, p.getPreferredOrFirst(Arrays.asList(s2Ger, s1Ger)));
	}

	@Test
	public void testEnglishAndGermanPreference() {
		final LanguagePreference p = new LanguagePreference("en", "de");
		assertNull(p.getPreferredOrFirst(null));
		assertNull(p.getPreferredOrFirst(Collections.emptyList()));
		assertSame(s1Eng, p.getPreferredOrFirst(Arrays.asList(s1Eng)));
		assertSame(s1Eng, p.getPreferredOrFirst(Arrays.asList(s1Eng, s2Ger)));
		assertSame(s1Eng, p.getPreferredOrFirst(Arrays.asList(s1Eng, s2Eng)));
		assertSame(s3Eng, p.getPreferredOrFirst(Arrays.asList(s2Ger, s3Eng)));
		assertSame(s2Ger, p.getPreferredOrFirst(Arrays.asList(s2Ger, s1Ger)));
	}

	@Test
	public void testGermanAndEnglishPreference() {
		final LanguagePreference p = new LanguagePreference("de", "en");
		assertNull(p.getPreferredOrFirst(null));
		assertNull(p.getPreferredOrFirst(Collections.emptyList()));
		assertSame(s1Eng, p.getPreferredOrFirst(Arrays.asList(s1Eng)));
		assertSame(s2Ger, p.getPreferredOrFirst(Arrays.asList(s1Eng, s2Ger)));
		assertSame(s1Eng, p.getPreferredOrFirst(Arrays.asList(s1Eng, s2Eng)));
		assertSame(s2Ger, p.getPreferredOrFirst(Arrays.asList(s2Ger, s3Eng)));
		assertSame(s2Ger, p.getPreferredOrFirst(Arrays.asList(s2Ger, s1Ger)));
	}

}

class MockLanguageDependentString {

	private final String value;
	private final String lang;

	public MockLanguageDependentString(String value, String lang) {
		super();
		this.value = value;
		this.lang = lang;
	}

	public String getValue() {
		return value;
	}

	public String getLang() {
		return lang;
	}

}