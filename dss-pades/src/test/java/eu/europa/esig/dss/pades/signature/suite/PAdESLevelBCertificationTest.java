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
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDocMDP;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class PAdESLevelBCertificationTest extends AbstractPAdESTestSignature {

	private DSSDocument originalDocument;

	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		originalDocument = new InMemoryDocument(getClass().getResourceAsStream("/pdf-two-fields.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.setLocation("Luxembourg");
		signatureParameters.setReason("DSS testing");
		signatureParameters.setAppName("DSS lib");
		signatureParameters.setContactInfo("Jira");
		signatureParameters.setPermission(CertificationPermission.MINIMAL_CHANGES_PERMITTED);
		SignatureImageParameters signatureImageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("TEST FIELD");
		signatureImageParameters.setTextParameters(textParameters);
		signatureImageParameters.getFieldParameters().setFieldId("signature-test");
		signatureParameters.setImageParameters(signatureImageParameters);

		service = new PAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected DSSDocument sign() {
		documentToSign = originalDocument;

		List<String> availableSignatureFields = service.getAvailableSignatureFields(documentToSign);
		assertEquals(2, availableSignatureFields.size());

		DSSDocument signedDoc = super.sign();
		assertNotNull(signedDoc);

		documentToSign = signedDoc;
		signatureParameters.setImageParameters(null);
		super.sign(); // should allow signing with /DodMDP P=2

		documentToSign = originalDocument;
		return signedDoc;
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		InMemoryDocument signedDoc = new InMemoryDocument(byteArray);
		List<String> availableSignatureFields = service.getAvailableSignatureFields(signedDoc);
		assertEquals(1, availableSignatureFields.size());
	}

	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		super.checkPdfRevision(diagnosticData);

		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());

		SignatureWrapper signatureWrapper = signatures.get(0);
		XmlPDFRevision pdfRevision = signatureWrapper.getPDFRevision();
		assertNotNull(pdfRevision);

		XmlPDFSignatureDictionary pdfSignatureDictionary = pdfRevision.getPDFSignatureDictionary();
		assertNotNull(pdfSignatureDictionary);

		XmlDocMDP docMDP = pdfSignatureDictionary.getDocMDP();
		assertNotNull(docMDP);
		assertEquals(CertificationPermission.MINIMAL_CHANGES_PERMITTED, docMDP.getPermissions());
	}

	@Override
	protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
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
