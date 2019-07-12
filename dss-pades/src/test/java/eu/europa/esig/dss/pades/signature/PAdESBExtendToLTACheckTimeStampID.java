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
package eu.europa.esig.dss.pades.signature;

import static org.junit.Assert.assertTrue;

import java.util.Date;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedObject;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedSignature;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;

public class PAdESBExtendToLTACheckTimeStampID extends PKIFactoryAccess {

	@Test
	public void test() throws Exception {
		DSSDocument documentToSign = new InMemoryDocument(PAdESBExtendToLTACheckTimeStampID.class.getResourceAsStream("/sample.pdf"));

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		ToBeSigned toBeSigned = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(toBeSigned, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

		signedDocument = service.extendDocument(signedDocument, signatureParameters);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());

		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnostic = report.getDiagnosticData();
		String signatureId = diagnostic.getFirstSignatureId();
		for (TimestampWrapper wrapper : diagnostic.getTimestampList(signatureId)) {
			boolean found = false;
			for (XmlTimestampedObject xmlTimestampedObject : wrapper.getTimestampedObjects()) {
				if (xmlTimestampedObject instanceof XmlTimestampedSignature) {
					String id = xmlTimestampedObject.getToken().getId();
					if (signatureId.equals(id)) {
						found = true;
					}
				}
			}
			assertTrue(found);
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
}
