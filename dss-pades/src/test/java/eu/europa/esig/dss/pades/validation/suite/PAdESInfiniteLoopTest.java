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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.spi.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import static java.time.Duration.ofMillis;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

// See DSS-1872
public class PAdESInfiniteLoopTest extends PKIFactoryAccess {
	
	@Test
	public void test() {
		assertTimeoutPreemptively(ofMillis(3000), () -> {
			DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/pades_infinite_loop.pdf"));
	
			PDFDocumentValidator validator = new PDFDocumentValidator(dssDocument);
			validator.setCertificateVerifier(getOfflineCertificateVerifier());
			validator.setSignaturePolicyProvider(new SignaturePolicyProvider());
			Reports reports = validator.validateDocument();
			assertNotNull(reports);
			// NOTE: OpenPDF and PDFBox search for signatures in opposite directions, therefore the results are different!
		});
	}
	
	@Test
	public void oppositeLoopTest() {
		assertTimeoutPreemptively(ofMillis(3000), () -> {
			DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/pades_opposite_infinite_loop.pdf"));
	
			PDFDocumentValidator validator = new PDFDocumentValidator(dssDocument);
			validator.setCertificateVerifier(getOfflineCertificateVerifier());
			validator.setSignaturePolicyProvider(new SignaturePolicyProvider());
			Reports reports = validator.validateDocument();
			assertNotNull(reports);
			// NOTE: OpenPDF and PDFBox search for signatures in opposite directions, therefore the results are different!
		});
	}
	
	@Override
	protected String getSigningAlias() {
		return null;
	}

}
