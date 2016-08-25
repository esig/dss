package eu.europa.esig.dss.utils.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.utils.IUtils;

public abstract class AbstractUtilsTest {

	private IUtils impl;

	@Before
	public void init() {
		impl = getImpl();
	}

	public abstract IUtils getImpl();

	@Test
	public void isStringEmpty() {
		assertTrue(impl.isStringEmpty(""));
		assertFalse(impl.isStringEmpty("  "));
		assertTrue(impl.isStringEmpty(null));
		assertFalse(impl.isStringEmpty("bla"));
	}

	@Test
	public void isStringNotEmpty() {
		assertFalse(impl.isStringNotEmpty(""));
		assertTrue(impl.isStringNotEmpty("  "));
		assertFalse(impl.isStringNotEmpty(null));
		assertTrue(impl.isStringNotEmpty("bla"));
	}

	@Test
	public void isStringBlank() {
		assertTrue(impl.isStringBlank(""));
		assertTrue(impl.isStringBlank("  "));
		assertTrue(impl.isStringBlank(null));
		assertFalse(impl.isStringBlank("bla"));
	}

	@Test
	public void isStringNotBlank() {
		assertFalse(impl.isStringNotBlank(""));
		assertFalse(impl.isStringNotBlank("  "));
		assertFalse(impl.isStringNotBlank(null));
		assertTrue(impl.isStringNotBlank("bla"));
	}

	@Test
	public void areStringsEqual() {
		assertTrue(impl.areStringsEqual(null, null));
		assertTrue(impl.areStringsEqual("", ""));
		assertFalse(impl.areStringsEqual("", "123"));
		assertFalse(impl.areStringsEqual("123", "456"));
		assertFalse(impl.areStringsEqual(null, ""));
		assertTrue(impl.areStringsEqual("bla", "bla"));
		assertFalse(impl.areStringsEqual("bla", "BLA"));
	}

	@Test
	public void areStringsEqualIgnoreCase() {
		assertTrue(impl.areStringsEqualIgnoreCase(null, null));
		assertTrue(impl.areStringsEqualIgnoreCase("", ""));
		assertFalse(impl.areStringsEqualIgnoreCase("", "123"));
		assertFalse(impl.areStringsEqualIgnoreCase("123", "456"));
		assertFalse(impl.areStringsEqualIgnoreCase(null, ""));
		assertTrue(impl.areStringsEqualIgnoreCase("bla", "bla"));
		assertTrue(impl.areStringsEqualIgnoreCase("bla", "BLA"));
	}

	@Test
	public void isStringDigits() {
		assertFalse(impl.isStringDigits(""));
		assertFalse(impl.isStringDigits(null));
		assertFalse(impl.isStringDigits("bla"));
		assertTrue(impl.isStringDigits("123"));
		assertFalse(impl.isStringDigits("123BLA"));
	}

	@Test
	public void trim() {
		assertEquals(null, impl.trim(null));
		assertEquals("", impl.trim(""));
		assertEquals("", impl.trim("   "));
		assertEquals("AAA", impl.trim(" AAA  "));
		assertEquals("AA A", impl.trim(" AA A  "));
	}

	@Test
	public void joinStrings() {
		assertEquals(null, impl.joinStrings(null, null));
		assertEquals("", impl.joinStrings(new ArrayList<String>(), null));
		assertEquals("", impl.joinStrings(new ArrayList<String>(), ","));

		List<String> list = new ArrayList<String>();
		list.add("a");
		list.add("b");
		list.add("c");

		assertEquals("a,b,c", impl.joinStrings(list, ","));
		assertEquals("abc", impl.joinStrings(list, ""));
	}

	@Test
	public void substringAfter() {
		assertEquals(null, impl.substringAfter(null, null));
		assertEquals("", impl.substringAfter("", null));
		assertEquals("bbb", impl.substringAfter("aaaaa?bbb", "?"));
	}

	@Test
	public void endsWithIgnoreCase() {
		assertTrue(impl.endsWithIgnoreCase("hello", "lo"));
		assertFalse(impl.endsWithIgnoreCase("hello", null));
		assertFalse(impl.endsWithIgnoreCase(null, "lo"));
		assertFalse(impl.endsWithIgnoreCase("hello", "la"));
	}

	@Test
	public void lowerCase() {
		assertEquals(null, impl.lowerCase(null));
		assertEquals("", impl.lowerCase(""));
		assertEquals(" ", impl.lowerCase(" "));
		assertEquals("aaaa", impl.lowerCase("AaAa"));
		assertEquals("aaaa-_&", impl.lowerCase("AaAa-_&"));
	}

	@Test
	public void upperCase() {
		assertEquals(null, impl.upperCase(null));
		assertEquals("", impl.upperCase(""));
		assertEquals(" ", impl.upperCase(" "));
		assertEquals("AAAA", impl.upperCase("AaAa"));
		assertEquals("AAAA-_&", impl.upperCase("AaAa-_&"));
	}

	@Test
	public void isArrayEmptyObj() {
		assertTrue(impl.isArrayEmpty(new Object[] {}));
		assertFalse(impl.isArrayEmpty(new Object[] { null }));
		assertFalse(impl.isArrayEmpty(new Object[] { "1", 1 }));
	}

	@Test
	public void isArrayNotEmptyObj() {
		assertFalse(impl.isArrayNotEmpty(new Object[] {}));
		assertTrue(impl.isArrayNotEmpty(new Object[] { null }));
		assertTrue(impl.isArrayNotEmpty(new Object[] { "1", 1 }));
	}

	@Test
	public void isArrayNotEmpty() {
		assertFalse(impl.isArrayNotEmpty(new byte[] {}));
		assertTrue(impl.isArrayNotEmpty(new byte[] { 1 }));
	}

	@Test
	public void isArrayEmpty() {
		assertTrue(impl.isArrayEmpty(new byte[] {}));
		assertFalse(impl.isArrayEmpty(new byte[] { 1 }));
	}

	@Test
	public void subarray() {
		byte[] array = new byte[] { 1, 2, 3, 4, 5 };
		assertTrue(Arrays.equals(array, impl.subarray(array, 0, array.length)));
		assertTrue(Arrays.equals(new byte[] { 1, 2, 3 }, impl.subarray(array, 0, 3)));
		assertTrue(Arrays.equals(new byte[] {}, impl.subarray(array, 0, 0)));
		assertTrue(Arrays.equals(null, impl.subarray(null, 0, 0)));
	}

	@Test
	public void isTrue() {
		assertFalse(impl.isTrue(null));
		assertFalse(impl.isTrue(false));
		assertTrue(impl.isTrue(true));
		assertTrue(impl.isTrue(Boolean.TRUE));
	}

	@Test
	public void isCollectionEmpty() {
		assertTrue(impl.isCollectionEmpty(null));
		assertTrue(impl.isCollectionEmpty(new ArrayList<String>()));

		List<String> list = new ArrayList<String>();
		list.add("a");
		list.add("b");
		list.add("c");
		assertFalse(impl.isCollectionEmpty(list));
	}

	@Test
	public void isCollectionNotEmpty() {
		assertFalse(impl.isCollectionNotEmpty(null));
		assertFalse(impl.isCollectionNotEmpty(new ArrayList<String>()));

		List<String> list = new ArrayList<String>();
		list.add("a");
		list.add("b");
		list.add("c");
		assertTrue(impl.isCollectionNotEmpty(list));
	}

	@Test
	public void collectionSize() {
		assertEquals(0, impl.collectionSize(new ArrayList<String>()));

		List<String> list = new ArrayList<String>();
		list.add("a");
		list.add("b");
		list.add("c");
		assertEquals(3, impl.collectionSize(list));
	}

	@Test
	public void toHex() {
		assertEquals("", impl.toHex(new byte[] {}));
		assertEquals("0102030405", impl.toHex(new byte[] { 1, 2, 3, 4, 5 }));
		assertEquals("61027a6a09", impl.toHex(new byte[] { 'a', 2, 'z', 'j', 9 }));
	}

	@Test
	public void toBase64() {
		assertEquals("", impl.toBase64(new byte[] {}));
		assertEquals("AQIDBAU=", impl.toBase64(new byte[] { 1, 2, 3, 4, 5 }));
	}

	@Test
	public void fromBase64() {
		assertTrue(Arrays.equals(new byte[] { 1, 2, 3, 4, 5 }, impl.fromBase64("AQIDBAU=")));
		assertTrue(Arrays.equals(new byte[] { 1, 2, 3, 4, 5 }, impl.fromBase64("\nAQI\nD BA\tU=\n")));
	}

	@Test
	public void toByteArray() throws UnsupportedEncodingException, IOException {
		String newFileName = "target/sample.txt";
		String newFileContent = "Hello world!";

		FileOutputStream fos = new FileOutputStream(newFileName);
		fos.write(newFileContent.getBytes("UTF-8"));
		fos.close();
		assertTrue(Arrays.equals(newFileContent.getBytes("UTF-8"), impl.toByteArray(new FileInputStream(newFileName))));
	}

	@Test
	public void closeQuietly() throws IOException {
		impl.closeQuietly(null);
		String newFileName = "target/sample2.txt";
		String newFileContent = "Hello world!";

		FileOutputStream fos = new FileOutputStream(newFileName);
		fos.write(newFileContent.getBytes("UTF-8"));
		fos.close();

		impl.closeQuietly(new FileInputStream(newFileName));
		impl.closeQuietly(new FileOutputStream("target/sample3.txt"));
	}

}
