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
package eu.europa.esig.dss.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

public class DigestDocumentTest {

	@Test
	public void test() {
		String base64EncodeDigest = "aaa";
		DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA1, base64EncodeDigest);
		assertEquals(base64EncodeDigest, doc.getDigest(DigestAlgorithm.SHA1));
	}

	@Test
	public void testNullDigestAlgo() {
		assertThrows(NullPointerException.class, () -> new DigestDocument(null, "aaaa"));
	}

	@Test
	public void testNullDigestAlgoValue() {
		assertThrows(NullPointerException.class, () -> new DigestDocument(DigestAlgorithm.SHA1, null));
	}

	@Test
	public void testUnknownDigest() {
		Exception exception = assertThrows(DSSException.class, () -> {
			String base64EncodeDigest = "aaa";
			DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA1, base64EncodeDigest);
			doc.getDigest(DigestAlgorithm.SHA256);
		});
		assertEquals("The digest document does not contain a digest value for the algorithm : SHA256", exception.getMessage());
	}

	@Test
	public void testOpenStream() {
		Exception exception = assertThrows(DSSException.class, () -> {
			String base64EncodeDigest = "aaa";
			DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA1, base64EncodeDigest);
			doc.openStream();
		});
		assertEquals("Not possible with Digest document", exception.getMessage());
	}

	@Test
	public void testSave() throws IOException {
		Exception exception = assertThrows(DSSException.class, () -> {
			String base64EncodeDigest = "aaa";
			DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA1, base64EncodeDigest);
			doc.save("target/test");
		});
		assertEquals("Not possible with Digest document", exception.getMessage());
	}

	@Test
	public void defaultConstructorTest() throws IOException, NoSuchAlgorithmException {
		Security.addProvider(new BouncyCastleProvider());
		byte[] stringToEncode = "aaa".getBytes();
		DigestDocument doc = new DigestDocument();
		for (DigestAlgorithm digestAlgorithm : DigestAlgorithm.values()) {
			doc.addDigest(digestAlgorithm, Base64.getEncoder().encodeToString(digestAlgorithm.getMessageDigest().digest(stringToEncode)));
		}
		for (DigestAlgorithm digestAlgorithm : DigestAlgorithm.values()) {
			assertNotNull(doc.getDigest(digestAlgorithm));
		}
		Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
	}

}
