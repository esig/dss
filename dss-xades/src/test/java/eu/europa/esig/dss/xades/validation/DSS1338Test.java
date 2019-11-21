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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.UnsupportedEncodingException;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.DefaultDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1338Test {

	@Test
	public void test() throws UnsupportedEncodingException {
		DSSDocument doc = new FileDocument("src/test/resources/validation/11068_signed.xml");
		DefaultDocumentValidator validator = DefaultDocumentValidator.fromDocument(doc);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		String firstSignatureId = reports.getSimpleReport().getFirstSignatureId();

		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(firstSignatureId);
		assertEquals(1, originalDocuments.size());

		boolean found = false;
		for (DSSDocument dssDocument : originalDocuments) {
			byte[] byteArray = DSSUtils.toByteArray(dssDocument);
			String signedContent = new String(byteArray, "UTF-8");
			if (signedContent.contains("<ns2:flusso xmlns:ns2=\"http://www.bancaditalia.it") && signedContent.endsWith("</ns2:flusso>")) {
				found = true;
			}
		}
		assertTrue(found);
	}

}
