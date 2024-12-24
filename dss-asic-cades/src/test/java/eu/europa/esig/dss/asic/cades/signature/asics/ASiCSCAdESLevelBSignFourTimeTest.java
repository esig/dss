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
package eu.europa.esig.dss.asic.cades.signature.asics;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ASiCSCAdESLevelBSignFourTimeTest extends AbstractASiCSCAdESTestSignature {

	private DSSDocument originalDocument;

	private DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> service;
	private ASiCWithCAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		originalDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text");

		signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

		service = new ASiCWithCAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected DSSDocument sign() {
		documentToSign = originalDocument;
		DSSDocument signedDocument = super.sign();

		signatureParameters.bLevel().setSigningDate(new Date());
		documentToSign = signedDocument;
		signedDocument = super.sign();

		signatureParameters.bLevel().setSigningDate(new Date());
		documentToSign = signedDocument;
		signedDocument = super.sign();

		signatureParameters.bLevel().setSigningDate(new Date());
		documentToSign = signedDocument;
		signedDocument = super.sign();

		documentToSign = originalDocument;
		return signedDocument;
	}

	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		return validator;
	}

	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		assertEquals(4, diagnosticData.getSignatures().size());
	}

	@Override
	protected void checkSigningDate(DiagnosticData diagnosticData) {
		// skip
	}

	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);

		for (String sigId : simpleReport.getSignatureIdList()) {
			assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(sigId));
		}
	}

	@Override
	protected DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
