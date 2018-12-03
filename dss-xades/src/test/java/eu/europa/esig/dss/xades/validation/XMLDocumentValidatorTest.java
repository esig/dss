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
package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Constructor;

import org.junit.Test;

import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;

public class XMLDocumentValidatorTest {

	private static XMLDocumentValidator VALIDATOR;

	static {
		try {
			Constructor<XMLDocumentValidator> defaultAndPrivateConstructor = XMLDocumentValidator.class.getDeclaredConstructor();
			defaultAndPrivateConstructor.setAccessible(true);
			VALIDATOR = defaultAndPrivateConstructor.newInstance();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Test
	public void isSupported() {
		byte[] wrongBytes = new byte[] { 1, 2 };
		assertFalse(VALIDATOR.isSupported(new InMemoryDocument(wrongBytes)));
		assertFalse(VALIDATOR.isSupported(new InMemoryDocument(wrongBytes, "test", MimeType.PDF)));
		assertFalse(VALIDATOR.isSupported(new InMemoryDocument(wrongBytes, "test")));

		assertTrue(VALIDATOR.isSupported(new InMemoryDocument(wrongBytes, "test", MimeType.XML)));
		assertTrue(VALIDATOR.isSupported(new InMemoryDocument(wrongBytes, "test.xml")));
		assertTrue(VALIDATOR.isSupported(new InMemoryDocument(new byte[] { '<', '?', 'x', 'm', 'l' })));
	}

}
