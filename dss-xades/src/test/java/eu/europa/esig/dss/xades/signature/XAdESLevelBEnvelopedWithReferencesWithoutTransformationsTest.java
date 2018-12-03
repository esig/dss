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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESLevelBEnvelopedWithReferencesWithoutTransformationsTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	private DSSDocument attachment1;
	private DSSDocument attachment2;

	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		// Load any two files (rather not XML) to sign them
		attachment1 = createDocument("src/test/resources/sample.txt");
		attachment2 = createDocument("src/test/resources/sample.png");

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		List<DSSReference> references = new ArrayList<DSSReference>();
		references.add(createReference(documentToSign));
		references.add(createReference(attachment1));
		references.add(createReference(attachment2));

		signatureParameters.setReferences(references);

		service = new XAdESService(getCompleteCertificateVerifier());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	private DSSDocument createDocument(String filePath) throws IOException {
		File file = new File(filePath);
		byte[] content = Utils.toByteArray(new FileInputStream(file));
		return new InMemoryDocument(content, filePath);
	}

	private DSSReference createReference(DSSDocument fileDocument) {
		DSSReference reference = new DSSReference();
		reference.setId("r-" + fileDocument.getName());
		reference.setUri(fileDocument.getName());
		reference.setContents(fileDocument);
		reference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		return reference;
	}

	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());

		List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
		detachedContents.add(documentToSign);
		detachedContents.add(attachment1);
		detachedContents.add(attachment2);
		validator.setDetachedContents(detachedContents);

		return validator;
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

}
