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
package eu.europa.esig.dss.cades.signature;

import static org.junit.Assert.assertEquals;

import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.reports.SimpleReport;

public class CAdESLevelBOnlySigningCertTest extends AbstractCAdESTestSignature {

	private DocumentSignatureService<CAdESSignatureParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello World".getBytes());

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		// Cert chain omitted
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);

		service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);
		
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

}
