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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import org.apache.commons.io.input.BOMInputStream;
import org.junit.Test;

public class BOMTest {

	@Test
	public void test() throws IOException {
		ApacheCommonsUtils acu = new ApacheCommonsUtils();

		FileInputStream fis = new FileInputStream(new File("src/test/resources/lotl_utf-8-sansbom.xml"));
		FileInputStream fisBom = new FileInputStream(new File("src/test/resources/lotl_utf-8.xml"));

		assertNotEquals(acu.toBase64(acu.toByteArray(fis)), acu.toBase64(acu.toByteArray(fisBom)));

		fis = new FileInputStream(new File("src/test/resources/lotl_utf-8-sansbom.xml"));
		fisBom = new FileInputStream(new File("src/test/resources/lotl_utf-8.xml"));

		BOMInputStream bomIS = new BOMInputStream(fis);
		BOMInputStream bomISSkipped = new BOMInputStream(fisBom);

		assertEquals(acu.toBase64(acu.toByteArray(bomIS)), acu.toBase64(acu.toByteArray(bomISSkipped)));
	}

}
