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
package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertTrue;

import java.util.Date;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class CAdESLTACheckTimeStampedTimestampIDTest extends PKIFactoryAccess {

	@Test
	public void test() throws Exception {
		DSSDocument documentToSign = new InMemoryDocument("Hello World".getBytes());

		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);

		CAdESService service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		ToBeSigned toBeSigned = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(toBeSigned, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		final DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());

		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnostic = report.getDiagnosticData();
		String timestampId = diagnostic.getSignatures().get(0).getTimestampList().get(0).getId();
		for (TimestampWrapper wrapper : diagnostic.getTimestampList(diagnostic.getFirstSignatureId())) {
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(wrapper.getType())) {
				boolean coverPreviousTsp = false;
				List<String> timestampedTimestampIds = wrapper.getTimestampedTimestampIds();
				for (String id : timestampedTimestampIds) {
					if (timestampId.equals(id)) {
						coverPreviousTsp = true;
					}
				}
				assertTrue(coverPreviousTsp);
			}
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
}
