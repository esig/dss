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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

public class DigestDocumentTest {

	@Test
	public void test() {
		String base64EncodeDigest = "aaa";
		DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA1, base64EncodeDigest);
		assertEquals(base64EncodeDigest, doc.getDigest(DigestAlgorithm.SHA1));
	}

	@Test(expected = DSSException.class)
	public void testUnknownDigest() {
		String base64EncodeDigest = "aaa";
		DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA1, base64EncodeDigest);
		doc.getDigest(DigestAlgorithm.SHA256);
	}

	@Test(expected = DSSException.class)
	public void testOpenStream() {
		String base64EncodeDigest = "aaa";
		DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA1, base64EncodeDigest);
		doc.openStream();
	}

	@Test(expected = DSSException.class)
	public void testSave() throws IOException {
		String base64EncodeDigest = "aaa";
		DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA1, base64EncodeDigest);
		doc.save("target/test");
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
