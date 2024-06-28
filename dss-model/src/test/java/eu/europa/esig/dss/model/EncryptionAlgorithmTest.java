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
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;

class EncryptionAlgorithmTest {

	@Test
	void forName() {
		assertEquals(EncryptionAlgorithm.RSA, EncryptionAlgorithm.forName(EncryptionAlgorithm.RSA.getName()));
	}

	@Test
	void forNameException() {
		Exception exception = assertThrows(IllegalArgumentException.class, () -> EncryptionAlgorithm.forName("aaa"));
		assertEquals("Unsupported algorithm: aaa", exception.getMessage());
	}

	@Test
	void forNameSubstitution() {
		assertEquals(EncryptionAlgorithm.RSA, EncryptionAlgorithm.forName("aaa", EncryptionAlgorithm.RSA));
	}

	@Test
	void forNameECDSA() {
		assertEquals(EncryptionAlgorithm.ECDSA, EncryptionAlgorithm.forName("EC"));
		assertEquals(EncryptionAlgorithm.ECDSA, EncryptionAlgorithm.forName("ECC"));
	}

	@Test
	void forOID() {
		assertEquals(EncryptionAlgorithm.RSA, EncryptionAlgorithm.forOID(EncryptionAlgorithm.RSA.getOid()));
	}

	@Test
	void forOIDException() {
		Exception exception = assertThrows(IllegalArgumentException.class, () -> EncryptionAlgorithm.forOID("aaa"));
		assertEquals("Unsupported algorithm: aaa", exception.getMessage());
	}

}
