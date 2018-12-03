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
package eu.europa.esig.dss.pades.signature.visible;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.pades.CertificationPermission;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.AbstractPAdESTestSignature;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;

public class PAdESLevelBCertificationTest extends AbstractPAdESTestSignature {

	private DocumentSignatureService<PAdESSignatureParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/pdf-two-fields.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.setLocation("Luxembourg");
		signatureParameters.setReason("DSS testing");
		signatureParameters.setContactInfo("Jira");
		signatureParameters.setPermission(CertificationPermission.MINIMAL_CHANGES_PERMITTED);
		signatureParameters.setSignatureFieldId("signature-test");
		SignatureImageParameters signatureImageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("TEST FIELD");
		signatureImageParameters.setTextParameters(textParameters);
		signatureParameters.setSignatureImageParameters(signatureImageParameters);

		service = new PAdESService(getCompleteCertificateVerifier());
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		try {
			PDDocument document = PDDocument.load(byteArray);
			COSBase docMDP = null;
			COSBase perms = document.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.PERMS);
			if (perms instanceof COSDictionary) {
				COSDictionary permsDict = (COSDictionary) perms;
				docMDP = permsDict.getDictionaryObject(COSName.DOCMDP);
			}
			assertNotNull(docMDP);
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	@Override
	protected DocumentSignatureService<PAdESSignatureParameters> getService() {
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
