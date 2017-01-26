package eu.europa.esig.dss.utils.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractUtilsTest {

	@Test
	public void isStringEmpty() {
		assertTrue(Utils.isStringEmpty(""));
		assertFalse(Utils.isStringEmpty("  "));
		assertTrue(Utils.isStringEmpty(null));
		assertFalse(Utils.isStringEmpty("bla"));
	}

	@Test
	public void isStringNotEmpty() {
		assertFalse(Utils.isStringNotEmpty(""));
		assertTrue(Utils.isStringNotEmpty("  "));
		assertFalse(Utils.isStringNotEmpty(null));
		assertTrue(Utils.isStringNotEmpty("bla"));
	}

	@Test
	public void isStringBlank() {
		assertTrue(Utils.isStringBlank(""));
		assertTrue(Utils.isStringBlank("  "));
		assertTrue(Utils.isStringBlank(null));
		assertFalse(Utils.isStringBlank("bla"));
	}

	@Test
	public void isStringNotBlank() {
		assertFalse(Utils.isStringNotBlank(""));
		assertFalse(Utils.isStringNotBlank("  "));
		assertFalse(Utils.isStringNotBlank(null));
		assertTrue(Utils.isStringNotBlank("bla"));
	}

	@Test
	public void areStringsEqual() {
		assertTrue(Utils.areStringsEqual(null, null));
		assertTrue(Utils.areStringsEqual("", ""));
		assertFalse(Utils.areStringsEqual("", "123"));
		assertFalse(Utils.areStringsEqual("123", "456"));
		assertFalse(Utils.areStringsEqual(null, ""));
		assertTrue(Utils.areStringsEqual("bla", "bla"));
		assertFalse(Utils.areStringsEqual("bla", "BLA"));
	}

	@Test
	public void areStringsEqualIgnoreCase() {
		assertTrue(Utils.areStringsEqualIgnoreCase(null, null));
		assertTrue(Utils.areStringsEqualIgnoreCase("", ""));
		assertFalse(Utils.areStringsEqualIgnoreCase("", "123"));
		assertFalse(Utils.areStringsEqualIgnoreCase("123", "456"));
		assertFalse(Utils.areStringsEqualIgnoreCase(null, ""));
		assertTrue(Utils.areStringsEqualIgnoreCase("bla", "bla"));
		assertTrue(Utils.areStringsEqualIgnoreCase("bla", "BLA"));
	}

	@Test
	public void isStringDigits() {
		assertFalse(Utils.isStringDigits(""));
		assertFalse(Utils.isStringDigits(null));
		assertFalse(Utils.isStringDigits("bla"));
		assertTrue(Utils.isStringDigits("123"));
		assertFalse(Utils.isStringDigits("123BLA"));
	}

	@Test
	public void trim() {
		assertEquals(null, Utils.trim(null));
		assertEquals("", Utils.trim(""));
		assertEquals("", Utils.trim("   "));
		assertEquals("AAA", Utils.trim(" AAA  "));
		assertEquals("AA A", Utils.trim(" AA A  "));
	}

	@Test
	public void joinStrings() {
		assertEquals(null, Utils.joinStrings(null, null));
		assertEquals("", Utils.joinStrings(new ArrayList<String>(), null));
		assertEquals("", Utils.joinStrings(new ArrayList<String>(), ","));

		List<String> list = new ArrayList<String>();
		list.add("a");
		list.add("b");
		list.add("c");

		assertEquals("a,b,c", Utils.joinStrings(list, ","));
		assertEquals("abc", Utils.joinStrings(list, ""));
	}

	@Test
	public void substringAfter() {
		assertEquals(null, Utils.substringAfter(null, null));
		assertEquals("", Utils.substringAfter("", null));
		assertEquals("bbb", Utils.substringAfter("aaaaa?bbb", "?"));
	}

	@Test
	public void endsWithIgnoreCase() {
		assertTrue(Utils.endsWithIgnoreCase("hello", "lo"));
		assertFalse(Utils.endsWithIgnoreCase("hello", null));
		assertFalse(Utils.endsWithIgnoreCase(null, "lo"));
		assertFalse(Utils.endsWithIgnoreCase("hello", "la"));
	}

	@Test
	public void lowerCase() {
		assertEquals(null, Utils.lowerCase(null));
		assertEquals("", Utils.lowerCase(""));
		assertEquals(" ", Utils.lowerCase(" "));
		assertEquals("aaaa", Utils.lowerCase("AaAa"));
		assertEquals("aaaa-_&", Utils.lowerCase("AaAa-_&"));
	}

	@Test
	public void upperCase() {
		assertEquals(null, Utils.upperCase(null));
		assertEquals("", Utils.upperCase(""));
		assertEquals(" ", Utils.upperCase(" "));
		assertEquals("AAAA", Utils.upperCase("AaAa"));
		assertEquals("AAAA-_&", Utils.upperCase("AaAa-_&"));
	}

	@Test
	public void isArrayEmptyObj() {
		assertTrue(Utils.isArrayEmpty(new Object[] {}));
		assertFalse(Utils.isArrayEmpty(new Object[] { null }));
		assertFalse(Utils.isArrayEmpty(new Object[] { "1", 1 }));
	}

	@Test
	public void isArrayNotEmptyObj() {
		assertFalse(Utils.isArrayNotEmpty(new Object[] {}));
		assertTrue(Utils.isArrayNotEmpty(new Object[] { null }));
		assertTrue(Utils.isArrayNotEmpty(new Object[] { "1", 1 }));
	}

	@Test
	public void isArrayNotEmpty() {
		assertFalse(Utils.isArrayNotEmpty(new byte[] {}));
		assertTrue(Utils.isArrayNotEmpty(new byte[] { 1 }));
	}

	@Test
	public void isArrayEmpty() {
		assertTrue(Utils.isArrayEmpty(new byte[] {}));
		assertFalse(Utils.isArrayEmpty(new byte[] { 1 }));
	}

	@Test
	public void subarray() {
		byte[] array = new byte[] { 1, 2, 3, 4, 5 };
		assertTrue(Arrays.equals(array, Utils.subarray(array, 0, array.length)));
		assertTrue(Arrays.equals(new byte[] { 1, 2, 3 }, Utils.subarray(array, 0, 3)));
		assertTrue(Arrays.equals(new byte[] {}, Utils.subarray(array, 0, 0)));
		assertTrue(Arrays.equals(null, Utils.subarray(null, 0, 0)));
	}

	@Test
	public void isTrue() {
		assertFalse(Utils.isTrue(null));
		assertFalse(Utils.isTrue(false));
		assertTrue(Utils.isTrue(true));
		assertTrue(Utils.isTrue(Boolean.TRUE));
	}

	@Test
	public void isCollectionEmpty() {
		assertTrue(Utils.isCollectionEmpty(null));
		assertTrue(Utils.isCollectionEmpty(new ArrayList<String>()));

		List<String> list = new ArrayList<String>();
		list.add("a");
		list.add("b");
		list.add("c");
		assertFalse(Utils.isCollectionEmpty(list));
	}

	@Test
	public void isCollectionNotEmpty() {
		assertFalse(Utils.isCollectionNotEmpty(null));
		assertFalse(Utils.isCollectionNotEmpty(new ArrayList<String>()));

		List<String> list = new ArrayList<String>();
		list.add("a");
		list.add("b");
		list.add("c");
		assertTrue(Utils.isCollectionNotEmpty(list));
	}

	@Test
	public void collectionSize() {
		assertEquals(0, Utils.collectionSize(new ArrayList<String>()));

		List<String> list = new ArrayList<String>();
		list.add("a");
		list.add("b");
		list.add("c");
		assertEquals(3, Utils.collectionSize(list));
	}

	@Test
	public void toHex() {
		assertEquals("", Utils.toHex(new byte[] {}));
		assertEquals("0102030405", Utils.toHex(new byte[] { 1, 2, 3, 4, 5 }));
		assertEquals("61027a6a09", Utils.toHex(new byte[] { 'a', 2, 'z', 'j', 9 }));
	}

	@Test
	public void toBase64() {
		assertEquals("", Utils.toBase64(new byte[] {}));
		assertEquals("AQIDBAU=", Utils.toBase64(new byte[] { 1, 2, 3, 4, 5 }));
	}

	@Test
	public void fromBase64() {
		assertTrue(Arrays.equals(new byte[] { 1, 2, 3, 4, 5 }, Utils.fromBase64("AQIDBAU=")));
		assertTrue(Arrays.equals(new byte[] { 1, 2, 3, 4, 5 }, Utils.fromBase64("\nAQI\nD BA\tU=\n")));
	}

	@Test
	public void toByteArray() throws UnsupportedEncodingException, IOException {
		String newFileName = "target/sample.txt";
		String newFileContent = "Hello world!";

		FileOutputStream fos = new FileOutputStream(newFileName);
		fos.write(newFileContent.getBytes("UTF-8"));
		fos.close();
		assertTrue(Arrays.equals(newFileContent.getBytes("UTF-8"), Utils.toByteArray(new FileInputStream(newFileName))));
	}

	@Test
	public void closeQuietly() throws IOException {
		Utils.closeQuietly(null);
		String newFileName = "target/sample2.txt";
		String newFileContent = "Hello world!";

		FileOutputStream fos = new FileOutputStream(newFileName);
		fos.write(newFileContent.getBytes("UTF-8"));
		fos.close();

		Utils.closeQuietly(new FileInputStream(newFileName));
		Utils.closeQuietly(new FileOutputStream("target/sample3.txt"));
	}

	@Test
	public void listFiles() {
		File folder = new File("src/main/java");
		String[] extensions = new String[] { "java" };
		Collection<File> listFiles = Utils.listFiles(folder, extensions, true);
		assertTrue(Utils.isCollectionNotEmpty(listFiles));

		extensions = new String[] { "doc", "pdf" };
		listFiles = Utils.listFiles(folder, extensions, true);
		assertTrue(Utils.isCollectionEmpty(listFiles));
	}
}
