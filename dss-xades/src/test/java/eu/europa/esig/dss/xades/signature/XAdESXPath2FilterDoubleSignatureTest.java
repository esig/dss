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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.XPath2FilterEnvelopedSignatureTransform;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESXPath2FilterDoubleSignatureTest extends PKIFactoryAccess {

	@Test
	public void test() throws IOException {

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESService service = new XAdESService(getOfflineCertificateVerifier());

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		setXPath2Transformation(toBeSigned, params, "REF1");

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		setXPath2Transformation(signedDocument, params, "REF2");

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doubleSignedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertEquals(2, signatureIdList.size());
		for (String signatureId : signatureIdList) {
			assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureId));
		}

		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(doubleSignedDocument));
	}
	
	private void setXPath2Transformation(DSSDocument documentToSign, XAdESSignatureParameters signatureParameters, String id) {

		List<DSSReference> dssReferences = new ArrayList<>();
		DSSReference reference = new DSSReference();
		reference.setContents(documentToSign);
		reference.setId(id);
		reference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		reference.setUri("");
		List<DSSTransform> transforms1 = new ArrayList<>();
		XPath2FilterEnvelopedSignatureTransform transform1 = new XPath2FilterEnvelopedSignatureTransform();
		transforms1.add(transform1);
		reference.setTransforms(transforms1);
		dssReferences.add(reference);

		signatureParameters.setReferences(dssReferences);
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
