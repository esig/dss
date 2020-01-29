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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxUtils;

public class PdfBoxUtilsTest {

	private static final String FILE = "/validation/doc-firmado-LT.pdf";

	@Test
	public void tesPdfBoxUtils() throws Exception {
		PDDocument document = PDDocument.load(getClass().getResourceAsStream(FILE));
		PdfDssDict dssDictionary = PdfBoxUtils.getDSSDictionary(document);
		assertNotNull(dssDictionary);
	}
	
	@Test
	public void tesPdfBoxUtilsEmptyDocument() throws Exception {
		PDDocument document = new PDDocument();
		PdfDssDict dssDictionary = PdfBoxUtils.getDSSDictionary(document);
		assertNull(dssDictionary);
	}
	
	@Test
	public void tesPdfBoxUtilsNull() throws Exception {
		Exception exception = assertThrows(NullPointerException.class, () ->  {
			PdfBoxUtils.getDSSDictionary(null);
		});
		assertEquals("PDDocument cannot be null!", exception.getMessage());
	}
}
