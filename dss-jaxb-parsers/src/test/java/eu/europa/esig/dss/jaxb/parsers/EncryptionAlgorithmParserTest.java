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
package eu.europa.esig.dss.jaxb.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;

class EncryptionAlgorithmParserTest {

	@Test
	void testEnum() {
		for (EncryptionAlgorithm ea : EncryptionAlgorithm.values()) {
			String string = EncryptionAlgorithmParser.print(ea);
			assertNotNull(string);
			EncryptionAlgorithm parse = EncryptionAlgorithmParser.parse(string);
			assertEquals(ea, parse);
		}
	}

	@Test
	void parseAlgos() {
		assertNotNull(EncryptionAlgorithmParser.parse("RSA"));
		assertNotNull(EncryptionAlgorithmParser.parse("DSA"));
		assertNotNull(EncryptionAlgorithmParser.parse("EC"));
		assertNotNull(EncryptionAlgorithmParser.parse("ECC"));
		assertNotNull(EncryptionAlgorithmParser.parse("PLAIN-ECDSA"));
		assertNotNull(EncryptionAlgorithmParser.parse("PLAIN_ECDSA"));
		assertNotNull(EncryptionAlgorithmParser.parse("Ed25519"));
		assertNotNull(EncryptionAlgorithmParser.parse("Ed448"));
	}
	
	@Test
	void unsupportedAlgorithmTest() {
		assertThrows(IllegalArgumentException.class, () -> EncryptionAlgorithmParser.parse("bla"));
	}

}
