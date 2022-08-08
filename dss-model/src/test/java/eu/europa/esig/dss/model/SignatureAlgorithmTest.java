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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
			if (sigAlgo.getUri() != null) {
				if (EncryptionAlgorithm.PLAIN_ECDSA.equals(sigAlgo.getEncryptionAlgorithm())) {
					sigAlgo = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, sigAlgo.getDigestAlgorithm());
				}
				assertEquals(sigAlgo, SignatureAlgorithm.forXML(sigAlgo.getUri()));
			}
		}
	}

	@Test
	public void forXMLWithDefault() {
		for (DigestAlgorithm digestAlgo : DigestAlgorithm.values()) {
			if (digestAlgo.getUri() != null) {
				SignatureAlgorithm sigAlgo = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, digestAlgo);
				if (sigAlgo != null) {
					assertEquals(sigAlgo, SignatureAlgorithm.forXML(digestAlgo.getUri(), sigAlgo));
				}
			}
		}
	}

	@Test
	public void forXMLException() {
		Exception exception = assertThrows(IllegalArgumentException.class, () -> SignatureAlgorithm.forXML("aaa"));
		assertEquals("Unsupported algorithm: aaa", exception.getMessage());
	}

	@Test
	public void forXMLSubstitution() {
		assertEquals(SignatureAlgorithm.RSA_SHA512, SignatureAlgorithm.forXML("aaa", SignatureAlgorithm.RSA_SHA512));
	}

	@Test
	public void forOid() {
		assertEquals(SignatureAlgorithm.RSA_SHA512, SignatureAlgorithm.forOID("1.2.840.113549.1.1.13"));
	}

	@Test
	public void forOidException() {
		Exception exception = assertThrows(IllegalArgumentException.class, () -> SignatureAlgorithm.forOID("1.2.3"));
		assertEquals("Unsupported algorithm: 1.2.3", exception.getMessage());
	}

	@Test
	public void forJWA() {
		for (SignatureAlgorithm sigAlgo : SignatureAlgorithm.values()) {
			if (sigAlgo.getJWAId() != null) {
				if (EncryptionAlgorithm.PLAIN_ECDSA.equals(sigAlgo.getEncryptionAlgorithm())) {
					sigAlgo = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, sigAlgo.getDigestAlgorithm());
				}
				assertEquals(sigAlgo, SignatureAlgorithm.forJWA(sigAlgo.getJWAId()));
			}
		}
	}

	@Test
	public void forJWAWithDefault() {
		for (DigestAlgorithm digestAlgo : DigestAlgorithm.values()) {
			if (digestAlgo.getJAdESId() != null) {
				SignatureAlgorithm sigAlgo = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, digestAlgo);
				if (sigAlgo != null) {
					assertEquals(sigAlgo, SignatureAlgorithm.forJWA(digestAlgo.getJAdESId(), sigAlgo));
				}
			}
		}
	}

	@Test
	public void forJWAException() {
		Exception exception = assertThrows(IllegalArgumentException.class, () -> SignatureAlgorithm.forJWA("aaa"));
		assertEquals("Unsupported algorithm: aaa", exception.getMessage());
	}

}
