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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.bouncycastle.cms.SignerInformation;
import org.junit.jupiter.api.BeforeEach;

import java.util.Collection;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelTTest extends AbstractCAdESTestSignature {

	private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello World".getBytes());

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);

		service = new CAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@Override
	protected Reports verify(DSSDocument signedDocument) {
		assertTrue(signedDocument instanceof CMSSignedDocument);
		CMSSignedDocument cmsSignedDocument = (CMSSignedDocument) signedDocument;
		Collection<SignerInformation> signers = cmsSignedDocument.getCMSSignedData().getSignerInfos().getSigners();
		assertEquals(1, signers.size());
		CAdESSignature cadesSignature = new CAdESSignature(cmsSignedDocument.getCMSSignedData(), signers.iterator().next());

		assertNotNull(cadesSignature.getSigningTime());
		assertEquals(DSSUtils.formatDateToRFC(signatureParameters.bLevel().getSigningDate()), DSSUtils.formatDateToRFC(cadesSignature.getSigningTime()));

		return super.verify(signedDocument);
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
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
	protected String getSigningAlias() {
		return GOOD_USER_WITH_PSEUDO;
	}

	@Override
	protected void verifyETSIValidationReport(ValidationReportType etsiValidationReportJaxb) {
		super.verifyETSIValidationReport(etsiValidationReportJaxb);

		for (SignatureValidationReportType signatureValidationReport : etsiValidationReportJaxb.getSignatureValidationReport()) {
			assertTrue(signatureValidationReport.getSignerInformation().isPseudonym());
		}
	}

	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);

		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(1, timestampList.size());
		TimestampWrapper timestampWrapper = timestampList.get(0);

		List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
		assertEquals(1, digestMatchers.size());

		XmlDigestMatcher xmlDigestMatcher = digestMatchers.get(0);
		assertEquals(DigestMatcherType.MESSAGE_IMPRINT, xmlDigestMatcher.getType());
		assertEquals(signatureParameters.getSignatureTimestampParameters().getDigestAlgorithm(), xmlDigestMatcher.getDigestMethod());

		assertEquals(DigestAlgorithm.SHA512, timestampWrapper.getDigestAlgorithm());
		assertEquals(EncryptionAlgorithm.RSA, timestampWrapper.getEncryptionAlgorithm());
	}

}
