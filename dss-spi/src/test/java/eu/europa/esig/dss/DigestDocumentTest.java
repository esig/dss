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
package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.junit.Test;

public class DigestDocumentTest {

	@Test
	public void test() {
		String base64EncodeDigest = "aaa";
		DigestDocument doc = new DigestDocument();
		doc.addDigest(DigestAlgorithm.SHA1, base64EncodeDigest);
		assertEquals(base64EncodeDigest, doc.getDigest(DigestAlgorithm.SHA1));
	}

	@Test(expected = DSSException.class)
	public void testUnknownDigest() {
		String base64EncodeDigest = "aaa";
		DigestDocument doc = new DigestDocument();
		doc.addDigest(DigestAlgorithm.SHA1, base64EncodeDigest);
		doc.getDigest(DigestAlgorithm.SHA256);
	}

	@Test(expected = DSSException.class)
	public void testOpenStream() {
		DigestDocument doc = new DigestDocument();
		doc.openStream();
	}

	@Test(expected = DSSException.class)
	public void testSave() throws IOException {
		DigestDocument doc = new DigestDocument();
		doc.save("target/test");
	}

}
