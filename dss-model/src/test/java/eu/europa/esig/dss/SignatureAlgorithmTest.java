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

import org.junit.Test;

public class SignatureAlgorithmTest {

	@Test
	public void getAlgorithm() {
		for (SignatureAlgorithm sigAlgo : SignatureAlgorithm.values()) {
			assertEquals(sigAlgo,
					SignatureAlgorithm.getAlgorithm(sigAlgo.getEncryptionAlgorithm(), sigAlgo.getDigestAlgorithm(), sigAlgo.getMaskGenerationFunction()));
		}
	}

	@Test
	public void forXML() {
		for (SignatureAlgorithm sigAlgo : SignatureAlgorithm.values()) {
			if (sigAlgo.getXMLId() != null) {
				assertEquals(sigAlgo, SignatureAlgorithm.forXML(sigAlgo.getXMLId()));
			}
		}
	}

	@Test(expected = DSSException.class)
	public void forXMLException() {
		SignatureAlgorithm.forXML("aaa");
	}

	@Test
	public void forXMLSubstitution() {
		assertEquals(SignatureAlgorithm.RSA_SHA512, SignatureAlgorithm.forXML("aaa", SignatureAlgorithm.RSA_SHA512));
	}

	@Test
	public void forOid() {
		assertEquals(SignatureAlgorithm.RSA_SHA512, SignatureAlgorithm.forOID("1.2.840.113549.1.1.13"));
	}

	@Test(expected = DSSException.class)
	public void forOidException() {
		SignatureAlgorithm.forOID("1.2.3");
	}

}
