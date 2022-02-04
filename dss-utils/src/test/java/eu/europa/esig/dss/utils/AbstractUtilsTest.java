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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractUtilsTest {
	
	@TempDir
    Path folder;

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
	public void areAllStringsEmpty() {
		String nullString = null;
		assertTrue(Utils.areAllStringsEmpty(nullString));
		assertTrue(Utils.areAllStringsEmpty(""));
		assertFalse(Utils.areAllStringsEmpty("  "));
		assertFalse(Utils.areAllStringsEmpty("bla"));
		assertTrue(Utils.areAllStringsEmpty("", nullString));
		assertFalse(Utils.areAllStringsEmpty("", " "));
		assertFalse(Utils.areAllStringsEmpty("bla", " "));
		assertTrue(Utils.areAllStringsEmpty("", "", ""));
		assertTrue(Utils.areAllStringsEmpty(nullString, nullString, nullString));
		assertFalse(Utils.areAllStringsEmpty("bla", " ", ""));
		assertFalse(Utils.areAllStringsEmpty("bla", " ", "bla"));
	}
	
	@Test
	public void isAtLeastOneStringNotEmpty() {
		String nullString = null;
		assertFalse(Utils.isAtLeastOneStringNotEmpty(nullString));
		assertFalse(Utils.isAtLeastOneStringNotEmpty(""));
		assertTrue(Utils.isAtLeastOneStringNotEmpty("  "));
		assertTrue(Utils.isAtLeastOneStringNotEmpty("bla"));
		assertFalse(Utils.isAtLeastOneStringNotEmpty("", nullString));
		assertTrue(Utils.isAtLeastOneStringNotEmpty("", " "));
		assertTrue(Utils.isAtLeastOneStringNotEmpty("bla", " "));
		assertFalse(Utils.isAtLeastOneStringNotEmpty("", "", ""));
		assertFalse(Utils.isAtLeastOneStringNotEmpty(nullString, nullString, nullString));
		assertTrue(Utils.isAtLeastOneStringNotEmpty("bla", " ", ""));
		assertTrue(Utils.isAtLeastOneStringNotEmpty("bla", " ", "bla"));
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
		assertFalse(Utils.isStringDigits("12 3"));
		assertFalse(Utils.isStringDigits("12-3"));
		assertFalse(Utils.isStringDigits("12.3"));
		assertFalse(Utils.isStringDigits("-123"));
		assertFalse(Utils.isStringDigits("+123"));
	}

	@Test
	public void trim() {
		assertNull(Utils.trim(null));
		assertEquals("", Utils.trim(""));
		assertEquals("", Utils.trim("   "));
		assertEquals("AAA", Utils.trim(" AAA  "));
		assertEquals("AA A", Utils.trim(" AA A  "));
	}

	@Test
	public void joinStrings() {
		assertNull(Utils.joinStrings(null, null));
		assertEquals("", Utils.joinStrings(new ArrayList<>(), null));
		assertEquals("", Utils.joinStrings(new ArrayList<>(), ","));

		List<String> list = new ArrayList<>();
		list.add("a");
		list.add("b");
		list.add("c");

		assertEquals("a,b,c", Utils.joinStrings(list, ","));
		assertEquals("abc", Utils.joinStrings(list, ""));
	}

	@Test
	public void substringAfter() {
		assertNull(Utils.substringAfter(null, null));
		assertEquals("", Utils.substringAfter("", null));
		assertEquals("bbb", Utils.substringAfter("aaaaa?bbb", "?"));
	}

	@Test
	public void endsWithIgnoreCase() {
		assertTrue(Utils.endsWithIgnoreCase("hello", "lo"));
		assertTrue(Utils.endsWithIgnoreCase("hello", "LO"));
		assertFalse(Utils.endsWithIgnoreCase("hello", null));
		assertFalse(Utils.endsWithIgnoreCase(null, "lo"));
		assertFalse(Utils.endsWithIgnoreCase("hello", "la"));
	}

	@Test
	public void getFileNameExtension() {
		assertEquals("xml", Utils.getFileNameExtension("file.xml"));
		assertEquals("pdf", Utils.getFileNameExtension("document.pdf"));
		assertEquals("pdf", Utils.getFileNameExtension("document..pdf"));
		assertEquals("pdf", Utils.getFileNameExtension("document.one.pdf"));
		assertEquals("java", Utils.getFileNameExtension("C:/root/demo.java"));
		assertEquals("java", Utils.getFileNameExtension("http://nowina.lu/demo.java"));
		assertEquals("", Utils.getFileNameExtension("document"));
		assertEquals("", Utils.getFileNameExtension("    "));
		assertEquals("", Utils.getFileNameExtension(""));
		assertNull(Utils.getFileNameExtension(null));
	}

	@Test
	public void lowerCase() {
		assertNull(Utils.lowerCase(null));
		assertEquals("", Utils.lowerCase(""));
		assertEquals(" ", Utils.lowerCase(" "));
		assertEquals("aaaa", Utils.lowerCase("AaAa"));
		assertEquals("aaaa-_&", Utils.lowerCase("AaAa-_&"));
	}

	@Test
	public void upperCase() {
		assertNull(Utils.upperCase(null));
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
		assertArrayEquals(array, Utils.subarray(array, 0, array.length));
		assertArrayEquals(new byte[] { 1, 2, 3 }, Utils.subarray(array, 0, 3));
		assertArrayEquals(new byte[] {}, Utils.subarray(array, 0, 0));
		assertArrayEquals(null, Utils.subarray(null, 0, 0));
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

		List<String> list = new ArrayList<>();
		list.add("a");
		list.add("b");
		list.add("c");
		assertFalse(Utils.isCollectionEmpty(list));
	}

	@Test
	public void isCollectionNotEmpty() {
		assertFalse(Utils.isCollectionNotEmpty(null));
		assertFalse(Utils.isCollectionNotEmpty(new ArrayList<String>()));

		List<String> list = new ArrayList<>();
		list.add("a");
		list.add("b");
		list.add("c");
		assertTrue(Utils.isCollectionNotEmpty(list));
	}
	
	@Test
	public void isMapEmpty() {
		assertTrue(Utils.isMapEmpty(null));
		assertTrue(Utils.isMapEmpty(new HashMap<String, Integer>()));
		
		Map<String, Boolean> map = new HashMap<>();
		map.put("a", true);
		map.put("b", false);
		map.put("c", true);
		assertFalse(Utils.isMapEmpty(map));
		assertEquals(3, map.size());
		
		map.clear();
		assertTrue(Utils.isMapEmpty(map));
	}
	
	@Test
	public void isMapNotEmpty() {
		assertFalse(Utils.isMapNotEmpty(null));
		assertFalse(Utils.isMapNotEmpty(new HashMap<String, Integer>()));
		
		Map<String, Boolean> map = new HashMap<>();
		map.put("a", true);
		map.put("b", false);
		map.put("c", true);
		assertTrue(Utils.isMapNotEmpty(map));
		assertEquals(3, map.size());
		
		map.clear();
		assertFalse(Utils.isMapNotEmpty(map));
	}

	@Test
	public void collectionSize() {
		assertEquals(0, Utils.collectionSize(null));

		assertEquals(0, Utils.collectionSize(new ArrayList<String>()));

		List<String> list = new ArrayList<>();
		list.add("a");
		list.add("b");
		list.add("c");
		assertEquals(3, Utils.collectionSize(list));
	}

	@Test
	public void isHexEncodedTest() {
		assertTrue(Utils.isHexEncoded(""));
		assertTrue(Utils.isHexEncoded("5361736861"));
		assertTrue(Utils.isHexEncoded("30187F47A8D9AE9D3D12942CE996C3BF746E4F4F"));
		assertTrue(Utils.isHexEncoded("7761726774655c657761723435684e554948672a264833345033"));
		assertFalse(Utils.isHexEncoded("\n536 1736 \n861"));
		assertFalse(Utils.isHexEncoded("5361736861=="));
		assertFalse(Utils.isHexEncoded("AQIDBAU"));
		assertFalse(Utils.isHexEncoded("AQIDBAU=="));
		assertFalse(Utils.isHexEncoded("1.3.5"));
		assertFalse(Utils.isHexEncoded("AS.DF,GH/JK"));
		assertThrows(NullPointerException.class, () -> Utils.isHexEncoded(null));
	}

	@Test
	public void toHexNull() {
		assertThrows(NullPointerException.class, () -> Utils.toHex(null));
	}

	@Test
	public void toHex() {
		assertEquals("", Utils.toHex(new byte[] {}));
		assertEquals("0102030405", Utils.toHex(new byte[] { 1, 2, 3, 4, 5 }));
		assertEquals("61027a6a09", Utils.toHex(new byte[] { 'a', 2, 'z', 'j', 9 }));
	}

	@Test
	public void fromHex() {
		assertNotNull(Utils.fromHex(""));
		assertArrayEquals(new byte[] { 1, 2, 3, 4, 5 }, Utils.fromHex("0102030405"));
		assertArrayEquals(new byte[] { 'a', 2, 'z', 'j', 9 }, Utils.fromHex("61027a6a09"));
		assertArrayEquals(new byte[] { 'a', 2, 'z', 'j', 9 }, Utils.fromHex("61027A6A09"));
	}

	@Test
	public void fromHexNull() {
		assertThrows(NullPointerException.class, () -> Utils.fromHex(null));
	}
	
	@Test
	public void isBase64Encoded() {
		assertTrue(Utils.isBase64Encoded(""));
		assertTrue(Utils.isBase64Encoded("AQIDBAU="));
		assertTrue(Utils.isBase64Encoded("AQIDBAU"));
		assertTrue(Utils.isBase64Encoded("AQIDBAU=="));
		assertTrue(Utils.isBase64Encoded("AQIDBAU==="));
		assertTrue(Utils.isBase64Encoded("\nAQI\nD BA\tU=\n"));
		assertFalse(Utils.isBase64Encoded("1.3.5"));
		assertFalse(Utils.isBase64Encoded("AS.DF,GH/JK"));
		assertThrows(NullPointerException.class, () -> Utils.isBase64Encoded(null));
	}
	
	@Test
	public void isBase64EncodedNullPointer() {
		assertThrows(NullPointerException.class, () -> Utils.isBase64Encoded(null));
	}

	@Test
	public void toBase64() {
		assertEquals("", Utils.toBase64(new byte[] {}));
		assertEquals("AQIDBAU=", Utils.toBase64(new byte[] { 1, 2, 3, 4, 5 }));
	}

	@Test
	public void fromBase64() {
		assertArrayEquals(new byte[] { 1, 2, 3, 4, 5 }, Utils.fromBase64("AQIDBAU="));
		assertArrayEquals(new byte[] { 1, 2, 3, 4, 5 }, Utils.fromBase64("\nAQI\nD BA\tU=\n"));
	}

	@Test
	public void toByteArray() throws UnsupportedEncodingException, IOException {
		String newFileName = "target/sample.txt";
		String newFileContent = "Hello world!";

		FileOutputStream fos = new FileOutputStream(newFileName);
		fos.write(newFileContent.getBytes("UTF-8"));
		fos.close();
		assertArrayEquals(newFileContent.getBytes("UTF-8"), Utils.toByteArray(new FileInputStream(newFileName)));
	}

	@Test
	public void toByteArrayCRLForLF() throws IOException, NoSuchAlgorithmException {

		try (InputStream is = AbstractUtilsTest.class.getResourceAsStream("/sample-lf.xml")) {
			byte[] byteArray = Utils.toByteArray(is);
			assertEquals("68ArneI9PhOBJytj5sP/zEewR2DkFObxewMY1wiUvak=", Utils.toBase64(MessageDigest.getInstance("SHA-256").digest(byteArray)));
		}
		
		try (InputStream is = AbstractUtilsTest.class.getResourceAsStream("/sample-cr-lf.xml")) {
			byte[] byteArray = Utils.toByteArray(is);
			assertEquals("kcDHOZjwZhVfuDhuhCeCERRmYpTH4Jj4RmfVVi31Q9g=", Utils.toBase64(MessageDigest.getInstance("SHA-256").digest(byteArray)));
		}

	}

	@Test
	public void closeQuietly() throws IOException {
		Utils.closeQuietly(null);
		String newFileName = "target/sample2.txt";
		String newFileContent = "Hello world!";

		FileOutputStream fos = new FileOutputStream(newFileName);
		fos.write(newFileContent.getBytes("UTF-8"));
		fos.close();
		assertTrue(new File(newFileName).exists());

		Utils.closeQuietly(new FileInputStream(newFileName));
		
		FileOutputStream sampleFos = new FileOutputStream("target/sample3.txt");
		Utils.closeQuietly(sampleFos);
		Utils.closeQuietly(sampleFos); // must handle closed

		File sample = new File("target/sample3.txt");
		assertTrue(sample.exists());
		assertTrue(sample.delete(), "Cannot delete the file");
		assertFalse(sample.exists());
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
	
	@Test
	public void getInputStreamSize() throws IOException {
		
		try (InputStream is = new ByteArrayInputStream("Hello World!".getBytes())) {
			assertEquals(12, Utils.getInputStreamSize(is));
		}
		
		try (InputStream emptyIs = new ByteArrayInputStream(new byte[0])) {
			assertEquals(0, Utils.getInputStreamSize(emptyIs));
		}

		String newFileName = "target/sample.txt";
		String newFileContent = "Hello world!\r\n";
		
		try (FileOutputStream fos = new FileOutputStream(newFileName)) {
			fos.write(newFileContent.getBytes("UTF-8"));
		}
		try (FileInputStream fileInputStream = new FileInputStream(newFileName)) {
			assertEquals(14, Utils.getInputStreamSize(fileInputStream));
		}
		
	}

	@Test
	public void clearDirectory() throws IOException {
		Path pathToFolder = folder.resolve("test");
		File dir = new File(pathToFolder.toString());
		dir.mkdir();
		Utils.cleanDirectory(dir);
		assertTrue(dir.exists());
		assertEquals(0, dir.list().length);
		assertTrue(dir.delete(), "Cannot delete the directory");
		assertFalse(dir.exists());
	}

	@Test
	public void clearDirectoryNotFound() throws FileNotFoundException {
		assertThrows(FileNotFoundException.class, () -> Utils.cleanDirectory(new File("wrong")));
	}

	@Test
	public void reverseListTest() {
		List<String> stringsList = Arrays.asList("a", "b", "c");
		assertEquals(Arrays.asList("c", "b", "a"), Utils.reverseList(stringsList));

		List<Integer> intList = Arrays.asList(1, 2, 3, null);
		assertEquals(Arrays.asList(null, 3, 2, 1), Utils.reverseList(intList));

		List<Object> emptyList = Collections.emptyList();
		assertEquals(0, Utils.reverseList(emptyList).size());

		assertThrows(Exception.class, () -> Utils.reverseList(null));
	}

	@Test
	public void containsAnyTest() {
		assertTrue(Utils.containsAny(Arrays.asList("c", "b", "a"), Arrays.asList("c", "b", "a")));
		assertTrue(Utils.containsAny(Arrays.asList("c", "b", "a"), Arrays.asList("a")));
		assertTrue(Utils.containsAny(Arrays.asList("c", "b", "a"), Arrays.asList("d", "c", "b", "a")));
		assertTrue(Utils.containsAny(Arrays.asList("c", "b", "a"), Arrays.asList("d", "a")));
		assertTrue(Utils.containsAny(Arrays.asList("c", "b", "a", "a"), Arrays.asList("d", "a")));
		assertTrue(Utils.containsAny(Arrays.asList("c", "b", "a"), Arrays.asList("d", "a", "a")));
		assertTrue(Utils.containsAny(Arrays.asList("c", "b", "a"), Arrays.asList("d", "d", "a")));
		assertTrue(Utils.containsAny(Arrays.asList("c", "b", "a", 10), Arrays.asList("a")));
		assertTrue(Utils.containsAny(Arrays.asList("c", "b", "a"), Arrays.asList("a", 10)));
		assertTrue(Utils.containsAny(new HashSet<>(Arrays.asList("c", "b", "a")), new HashSet<>(Arrays.asList("c", "b", "a"))));
		assertTrue(Utils.containsAny(new HashSet<>(Arrays.asList("c", "b", "a")), new HashSet<>(Arrays.asList("a"))));
		assertTrue(Utils.containsAny(new HashSet<>(Arrays.asList("c", "b", "a")), new HashSet<>(Arrays.asList("d", "c", "b", "a"))));
		assertTrue(Utils.containsAny(new HashSet<>(Arrays.asList("c", "b", "a")), new HashSet<>(Arrays.asList("d", "a"))));
		assertTrue(Utils.containsAny(Arrays.asList("c", "b", "a"), new HashSet<>(Arrays.asList("c", "b", "a"))));
		assertTrue(Utils.containsAny(Arrays.asList("c", "b", "a"), Arrays.asList("a")));
		assertTrue(Utils.containsAny(new HashSet<>(Arrays.asList("c", "b", "a")), Arrays.asList("d", "c", "b", "a")));
		assertTrue(Utils.containsAny(new HashSet<>(Arrays.asList("c", "b", "a")), Arrays.asList("d", "a")));
		assertTrue(Utils.containsAny(new HashSet<>(Arrays.asList("c", "b", "a", 1)), Arrays.asList("d", 1)));

		assertFalse(Utils.containsAny(Arrays.asList("c", "b", "a"), Arrays.asList("d", "e", "f")));
		assertFalse(Utils.containsAny(new HashSet<>(Arrays.asList("c", "b", "a")), new HashSet<>(Arrays.asList("d", "e", "f"))));
		assertFalse(Utils.containsAny(Arrays.asList("c", "b", "a"), new HashSet<>(Arrays.asList("d", "e", "f"))));
		assertFalse(Utils.containsAny(new HashSet<>(Arrays.asList("c", "b", "a")), Arrays.asList("d", "e", "f")));
		assertFalse(Utils.containsAny(Arrays.asList(), Arrays.asList("d", "e", "f")));
		assertFalse(Utils.containsAny(Arrays.asList("c", "b", "a"), Arrays.asList()));

		assertThrows(Exception.class, () -> Utils.containsAny(null, Arrays.asList("c", "b", "a")));
		assertThrows(Exception.class, () -> Utils.containsAny(Arrays.asList("c", "b", "a"), null));
		assertThrows(Exception.class, () -> Utils.containsAny(null, null));
	}

}
