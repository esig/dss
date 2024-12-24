/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

class SimpleCMSValidationTest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		String cmsBase64 = "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" + 
				"RYOtAAAAAAAA";
		return new InMemoryDocument(Utils.fromBase64(cmsBase64));
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		String signCertBase64 = "MIICwjCCAaygAwIBAgIBATALBgkqhkiG9w0BAQUwHjEcMAkGA1UEBhMCUlUwDwYD" + 
				"VQQDHggAVABlAHMAdDAeFw0xNjAxMzEyMzAwMDBaFw0xOTAxMzEyMzAwMDBaMB4x" + 
				"HDAJBgNVBAYTAlJVMA8GA1UEAx4IAFQAZQBzAHQwggEiMA0GCSqGSIb3DQEBAQUA" + 
				"A4IBDwAwggEKAoIBAQCm0iQwyVO6776gQXaaKbS+cWA6buhKc6JTcdtPgWjbpU82" + 
				"cljiv6MevI5rQ7pGt4I596CAf8U+H7qYHspuJ5wujgq2OXL9azqVZjf+ea2U6W2g" + 
				"IjyI5j3C/RtX5f9Y2tPZ7mcpSDinvmzDYe3uUS420fuCcZtFHxvNmc5VAzhpA3LU" + 
				"XmUlqtB+JH7oH94c3r+OM2jLDpTPVY39wJC34G4rxi670pq8T68o38dJnQfOVQ7V" + 
				"AKM/yiayBZnHXiVp+WOyD5LeMjU53FzUr1MalwYPAgFfuhBsRDQ/P+QXU2Z/gm3l" + 
				"N8rG+Q+n1rfbJIie+2G117iUSVoisSYkmljCNUlZAgMBAAGjDzANMAsGA1UdDwQE" + 
				"AwIAAjALBgkqhkiG9w0BAQUDggEBAG+AqBFL/U0ZdEfA7zpeMg9jMiOlJGQnpFZi" + 
				"/tM9erKUMUDzIVW+Dj6EWfcHfKv7uZi4yWpQ7ypZz3fB31K2Uf9BlX2heOsI6kH+" + 
				"Offi8rdccdc9h34qwtEszKX9I+wtvAuMDwaG+Dd5JPz0zz8fEPp7AHM7ATs51OSF" + 
				"2c2LvZHLFomnH1yZnreotfGTYfLnGiEUDdSpGNFy3JxxUdVbOpligBIakaV/AvY5" + 
				"FYCIRmYgt4H1uvV5wZKKprih+ZHRwQUBx//5qLJbYn3EAd43z5O7rK4kZy1b4bI8" + 
				"JETMliqNTr2HUnf9THZCR0515DpP0Fxx1sQmDMnlOOepBAq2s5M=";
		CertificateToken signingCertificate = DSSUtils.loadCertificateFromBase64EncodedString(signCertBase64);
		CommonCertificateSource commonCertificateSource = new CommonCertificateSource();
		commonCertificateSource.addCertificate(signingCertificate);
		validator.setSigningCertificateSource(commonCertificateSource);
		
		return validator;
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		assertNotNull(signature.getSigningCertificate());
		assertNull(signature.getSigningCertificateReference());		
	}
	
	@Override
	protected void checkSigningDate(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNull(signature.getClaimedSigningTime());
	}

}
