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
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DigestDocumentTest extends AbstractTestDSSDocument {

	@Test
	void testByteArray() {
		byte[] digest = "aaa".getBytes();
		DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA1, digest);
		assertArrayEquals(digest, doc.getDigestValue(DigestAlgorithm.SHA1));
	}

	@Test
	void testString() {
		String base64EncodeDigest = "aaa";
		DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA1, base64EncodeDigest);
		assertArrayEquals(Base64.getDecoder().decode(base64EncodeDigest), doc.getDigestValue(DigestAlgorithm.SHA1));
	}

	@Test
	void testNullDigestAlgo() {
		assertThrows(NullPointerException.class, () -> new DigestDocument(null, "aaaa".getBytes()));
	}

	@Test
	void testNullDigestAlgoValue() {
		assertThrows(NullPointerException.class, () -> new DigestDocument(DigestAlgorithm.SHA1, (byte[]) null));
	}

	@Test
	void testUnknownDigest() {
		String base64EncodeDigest = "aaa";
		DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA1, base64EncodeDigest);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> doc.getDigestValue(DigestAlgorithm.SHA256));
		assertEquals("The digest document does not contain a digest value for the algorithm : SHA256", exception.getMessage());
	}

	@Test
	void testOpenStream() {
		String base64EncodeDigest = "aaa";
		DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA1, base64EncodeDigest);
		Exception exception = assertThrows(UnsupportedOperationException.class, doc::openStream);
		assertEquals("Not possible with Digest document", exception.getMessage());
	}

	@Test
	void testSave() {
		String base64EncodeDigest = "aaa";
		DigestDocument doc = new DigestDocument(DigestAlgorithm.SHA1, base64EncodeDigest);
		Exception exception = assertThrows(UnsupportedOperationException.class, () -> doc.save("target/test"));
		assertEquals("Not possible with Digest document", exception.getMessage());
	}

	@Test
	void defaultConstructorTest() throws NoSuchAlgorithmException {
		Security.addProvider(new BouncyCastleProvider());
		byte[] stringToEncode = "aaa".getBytes();
		DigestDocument doc = new DigestDocument();
		for (DigestAlgorithm digestAlgorithm : DigestAlgorithm.values()) {
			// Not registered
			if (DigestAlgorithm.SHAKE128.equals(digestAlgorithm) || DigestAlgorithm.SHAKE256.equals(digestAlgorithm)) {
				continue;
			}
			doc.addDigest(digestAlgorithm, digestAlgorithm.getMessageDigest().digest(stringToEncode));
		}
		for (DigestAlgorithm digestAlgorithm : DigestAlgorithm.values()) {
			// Not registered
			if (DigestAlgorithm.SHAKE128.equals(digestAlgorithm) || DigestAlgorithm.SHAKE256.equals(digestAlgorithm)) {
				continue;
			}
			assertNotNull(doc.getDigestValue(digestAlgorithm));
		}
		Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
	}

	@Override
	protected DSSDocument getPersistenceTestDocument() {
		return new DigestDocument(DigestAlgorithm.SHA256, "aaa");
	}

	@Override
	protected List<DSSDocument> getPersistenceTestAlternativeDocuments() {
		DigestDocument multipleDigestDoc = new DigestDocument(DigestAlgorithm.SHA256, "aaa");
		multipleDigestDoc.addDigest(DigestAlgorithm.SHA1, "aa");
		return Arrays.asList(
				multipleDigestDoc,
				new DigestDocument(DigestAlgorithm.SHA1, "aaa"),
				new DigestDocument(DigestAlgorithm.SHA256, "bbb"),
				new DigestDocument(DigestAlgorithm.SHA256, "aaa", "digestDoc"),
				new DigestDocument(DigestAlgorithm.SHA256, "aaa", null, MimeTypeEnum.TEXT)
		);
	}

}
