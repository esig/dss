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

import eu.europa.esig.dss.model.DSSException;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PemToDerConverterTest {

	@Test
	public void testException() {
		Exception exception = assertThrows(DSSException.class, () -> PemToDerConverter.convert(new byte[] {}));
		assertEquals("Unable to read PEM Object", exception.getMessage());
	}

	@Test
	public void pemFile() throws IOException {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/belgium2.pem.crl")) {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			Streams.pipeAll(is, baos);
			byte[] converted = PemToDerConverter.convert(baos.toByteArray());
			assertTrue(converted != null && converted.length > 0);
		}
	}

}
