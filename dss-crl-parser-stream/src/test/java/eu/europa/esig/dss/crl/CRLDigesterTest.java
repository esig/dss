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
package eu.europa.esig.dss.crl;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

import eu.europa.esig.dss.utils.Utils;

public class CRLDigesterTest {

	private CRLParser parser = new CRLParser();

	@Test
	public void getDigest() throws IOException, GeneralSecurityException {
		try (InputStream is = CRLDigesterTest.class.getResourceAsStream("/belgium2.crl"); DigestInputStream dis = new DigestInputStream(is, getSHA1Digest())) {

			parser.processDigest(dis);

			byte[] digest = dis.getMessageDigest().digest();
			String computedBase64 = Utils.toBase64(digest);
			String expectedBase64Digest = "9G6GVRFhXI2bEXfhM98aXOsamXk=";
			assertEquals(computedBase64, expectedBase64Digest);
		}
	}

	private MessageDigest getSHA1Digest() throws NoSuchAlgorithmException {
		return MessageDigest.getInstance("SHA1");
	}

}
