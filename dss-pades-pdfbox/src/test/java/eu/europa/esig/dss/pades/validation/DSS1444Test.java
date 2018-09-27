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
package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.io.InputStream;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.Test;

import eu.europa.esig.dss.InMemoryDocument;

public class DSS1444Test {

	@Test
	public void test() throws Exception {
		try (InputStream is = getClass().getResourceAsStream("/EmptyPage-corrupted.pdf")) {
			PDDocument doc = PDDocument.load(is);
			assertNotNull(doc);
		}
	}

	@Test
	public void test2() throws Exception {
		try (InputStream is = getClass().getResourceAsStream("/EmptyPage-corrupted2.pdf")) {
			PDDocument doc = PDDocument.load(is);
			assertNotNull(doc);
		}
	}

	@Test(expected = IOException.class)
	public void test3() throws Exception {
		try (InputStream is = getClass().getResourceAsStream("/small-red.jpg")) {
			PDDocument.load(is);
		}
	}

	@Test
	public void test3bis() throws IOException {
		try (InputStream is = getClass().getResourceAsStream("/small-red.jpg")) {
			PDFDocumentValidator val = new PDFDocumentValidator(new InMemoryDocument(is));
			assertEquals(0, val.getSignatures().size());
		}
	}

}
