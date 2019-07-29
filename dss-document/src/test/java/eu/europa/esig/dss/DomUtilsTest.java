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

import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;

import org.junit.Test;

public class DomUtilsTest {

	private static final String XML_HEADER = "<?xml version='1.0' encoding='UTF-8'?>";
	private static final String XML_TEXT = "<hello><world></world></hello>";

	private static final String INCORRECT_XML_TEXT = "<hello><world></warld></hello>";

	@Test
	public void testNoHeader() {
		InputStream is = new ByteArrayInputStream(XML_TEXT.getBytes());
		assertNotNull(DomUtils.buildDOM(is));
		assertNotNull(DomUtils.buildDOM(XML_TEXT));
		assertNotNull(DomUtils.buildDOM(new InMemoryDocument(XML_TEXT.getBytes(), "my xml")));
	}

	@Test(expected = DSSException.class)
	public void testNoHeaderError() {
		DomUtils.buildDOM(INCORRECT_XML_TEXT);
	}

	@Test
	public void testHeader() {
		InputStream is = new ByteArrayInputStream((XML_HEADER + XML_TEXT).getBytes());
		assertNotNull(DomUtils.buildDOM(is));
		assertNotNull(DomUtils.buildDOM(XML_HEADER + XML_TEXT));
		assertNotNull(DomUtils.buildDOM(new InMemoryDocument((XML_HEADER + XML_TEXT).getBytes(), "my xml")));
	}

	@Test(expected = DSSException.class)
	public void testHeaderError() {
		DomUtils.buildDOM(XML_HEADER + INCORRECT_XML_TEXT);
	}

	@Test(expected = DSSException.class)
	public void testExpansionXml() throws Exception {
		assertNotNull(DomUtils.buildDOM(new FileInputStream("src/test/resources/xml_expansion.xml")));
	}

	@Test(expected = DSSException.class)
	public void testEntityXml() throws Exception {
		// Should ignore the URL embedded in the DTD
		DomUtils.buildDOM(new FileInputStream("src/test/resources/xml_entity.xml"));
	}

	@Test
	public void getSecureTransformer() {
		assertNotNull(DomUtils.getSecureTransformer());
	}

}
