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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class XAdESLevelBTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private DSSDocument documentToSign;

	private Date signingDate;
	private TimestampToken contentTimestamp;

	@BeforeEach
	public void init() throws Exception {
		service = new XAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		signingDate = new Date();
		contentTimestamp = service.getContentTimestamp(documentToSign, getSignatureParameters());
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		// Stateless mode
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		if (contentTimestamp != null) {
			signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));
		}
		return signatureParameters;
	}
	
	@Override
	protected void checkDTBSR(DiagnosticData diagnosticData) {
		super.checkDTBSR(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		XmlDigestAlgoAndValue dtbsr = signature.getDataToBeSignedRepresentation();
		
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, getSignatureParameters());
		assertArrayEquals(DSSUtils.digest(dtbsr.getDigestMethod(), dataToSign.getBytes()), dtbsr.getDigestValue());
	}

	@Override
	protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
		super.validateETSISignersDocument(signersDocument);

		DigestAlgAndValueType digestAlgoAndValue = getDigestAlgoAndValue(signersDocument);
		assertNotNull(digestAlgoAndValue);
		assertNotNull(digestAlgoAndValue.getDigestMethod());
		assertNotNull(digestAlgoAndValue.getDigestValue());

		List<ValidationObjectType> validationObjects = getValidationObjects(signersDocument);
		assertEquals(1, validationObjects.size());
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
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
