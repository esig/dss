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
package eu.europa.esig.dss.utils.apache.impl;

import org.apache.commons.io.input.BOMInputStream;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class BOMTest {

	@Test
	void test() throws IOException {
		ApacheCommonsUtils acu = new ApacheCommonsUtils();

		try (FileInputStream fis = new FileInputStream("src/test/resources/lotl_utf-8-sansbom.xml");
			 FileInputStream fisBom = new FileInputStream("src/test/resources/lotl_utf-8.xml")) {
			assertNotEquals(acu.toBase64(acu.toByteArray(fis)), acu.toBase64(acu.toByteArray(fisBom)));
		}

		try (FileInputStream fis = new FileInputStream("src/test/resources/lotl_utf-8-sansbom.xml");
			 FileInputStream fisBom = new FileInputStream("src/test/resources/lotl_utf-8.xml")) {

			BOMInputStream bomIS = BOMInputStream.builder().setInputStream(fis).get();
			BOMInputStream bomISSkipped = BOMInputStream.builder().setInputStream(fisBom).get();

			assertEquals(acu.toBase64(acu.toByteArray(bomIS)), acu.toBase64(acu.toByteArray(bomISSkipped)));
		}
	}

}
