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
package eu.europa.esig.dss.jades.validation;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

public class JWSCompactDocumentValidatorTest {

	@Test
	public void test() {
		
		JWSCompactDocumentValidator validator = new JWSCompactDocumentValidator();

		DSSDocument jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.2yUt5UtfsRK1pnN0KTTv7gzHTxwDqDz2OkFSqlbQ40A".getBytes());
		assertTrue(validator.isSupported(jws));
		jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9..c2lnaA".getBytes());
		assertTrue(validator.isSupported(jws));

		DSSDocument wrong = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA".getBytes());
		assertFalse(validator.isSupported(wrong));
		wrong = new InMemoryDocument("<".getBytes());
		assertFalse(validator.isSupported(wrong));
		wrong = new InMemoryDocument("%PDF".getBytes());
		assertFalse(validator.isSupported(wrong));
		wrong = new InMemoryDocument(new byte[] {});
		assertFalse(validator.isSupported(wrong));
	}
	
}
