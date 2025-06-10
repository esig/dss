/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Formatter;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DigestTest {
	
	private static final Logger LOG = LoggerFactory.getLogger(DigestTest.class);

	@Test
	void testEquals() throws Exception {

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] value = md.digest("Hello World !".getBytes());

		Digest d1 = new Digest(DigestAlgorithm.SHA256, value);
		Digest d2 = new Digest(DigestAlgorithm.SHA256, value);

		assertEquals(d1, d2);
		assertEquals(d1.hashCode(), d2.hashCode());
		assertArrayEquals(value, d1.getValue());
		assertArrayEquals(value, d2.getValue());

		assertEquals("07F2BDEF34ED16E3A1BA0DBB7E47B8FD981CE0CCB3E1BFE564D82C423CBA7E47", d1.getHexValue());
		assertEquals("07F2BDEF34ED16E3A1BA0DBB7E47B8FD981CE0CCB3E1BFE564D82C423CBA7E47", d2.getHexValue());
	}

	@Test
	void testSerializable() throws Exception {

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] value = md.digest("Hello World !".getBytes());

		Digest d1 = new Digest(DigestAlgorithm.SHA256, value);

		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(buffer);
		out.writeObject(d1);
		out.close();

		ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(buffer.toByteArray()));
		Digest d2 = (Digest) in.readObject();

		assertEquals(d1,d2);
		assertEquals(d1.hashCode(),d2.hashCode());

	}
	
	@Test
	void nullValues() {
		Digest digest = new Digest();
		assertNull(digest.getAlgorithm());
		assertNull(digest.getValue());
		assertThrows(NullPointerException.class, digest::getHexValue);
		assertNotNull(digest.toString());
	}

	@Test
	void stateless() {
		Digest d1 = new Digest(DigestAlgorithm.SHA256, new byte[] { 1, 2, 3 });
		String hexValue = d1.getHexValue();
		d1.setValue(new byte[] { 5, 6, 7 });
		assertNotEquals(hexValue, d1.getHexValue());
	}

	@Test
	void hexTest() {
		Digest d1 = new Digest(DigestAlgorithm.SHA256, new byte[] { 1, 2, 3 });
		assertEquals("010203", d1.getHexValue());
	}

	@Test
	void base64Test() {
		Digest d1 = new Digest(DigestAlgorithm.SHA256, new byte[] { 1, 2, 3 });
		assertEquals("AQID", d1.getBase64Value());
	}

	@Disabled("performances")
	void perfs() {

		int bigIntCounter = 0;
		int formatterCounter = 0;

		for (int x = 0; x < 100; x++) {

			byte[] value = new byte[500];

			SecureRandom random = new SecureRandom();
			random.nextBytes(value);

			String hex1 = null;
			String hex2 = null;

			long start = System.currentTimeMillis();
			for (int i = 0; i < 1_000; i++) {
				hex1 = new BigInteger(1, value).toString(16);
				if (hex1.length() % 2 == 1) {
					hex1 = "0" + hex1;
				}
				hex1 = hex1.toUpperCase(Locale.ENGLISH);
			}
			long end = System.currentTimeMillis();
			long durationBigInt = end - start;
			LOG.info("BigInt : {}", durationBigInt);

			long start2 = System.currentTimeMillis();
			for (int i = 0; i < 1_000; i++) {
				try (Formatter formatter = new Formatter()) {
					for (byte b : value) {
						formatter.format("%02X", b);
					}
					hex2 = formatter.toString();
				}
			}

			long end2 = System.currentTimeMillis();
			long durationFormatter = end2 - start2;
			LOG.info("formatter : {}", durationFormatter);

			if (durationBigInt < durationFormatter) {
				bigIntCounter++;
			} else {
				formatterCounter++;
			}

			assertEquals(hex1, hex2);
		}
		
		LOG.info("bigInt total : {}", bigIntCounter);
		LOG.info("formatter total : {}", formatterCounter);
	}
	
}
