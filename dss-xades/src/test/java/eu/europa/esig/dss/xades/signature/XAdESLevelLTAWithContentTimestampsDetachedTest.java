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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignerLocation;
import eu.europa.esig.dss.TimestampParameters;
import eu.europa.esig.dss.enumerations.CommitmentType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESLevelLTAWithContentTimestampsDetachedTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		documentToSign = new FileDocument(new File("src/test/resources/sample.png"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

		SignerLocation signerLocation = new SignerLocation();
		signerLocation.setCountry("BE");
		signerLocation.setLocality("Brussels");
		signerLocation.setStreet("Anspach");
		signatureParameters.bLevel().setSignerLocation(signerLocation);

		signatureParameters.bLevel()
				.setCommitmentTypeIndications(Arrays.asList(CommitmentType.ProofOfSender.getUri(), CommitmentType.ProofOfCreation.getUri()));

		signatureParameters.bLevel().setClaimedSignerRoles(Arrays.asList("Manager", "Administrator"));

		signatureParameters.setAddX509SubjectName(true);

		TimestampParameters contentTimestampParameters = new TimestampParameters();
		contentTimestampParameters.setCanonicalizationMethod(null); // The file cannot be canonicalized
		signatureParameters.setContentTimestampParameters(contentTimestampParameters);
		TimestampToken contentTimestamp = service.getContentTimestamp(documentToSign, signatureParameters);

		contentTimestampParameters = new TimestampParameters();
		contentTimestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
		contentTimestampParameters.setCanonicalizationMethod(null); // The file cannot be canonicalized
		signatureParameters.setContentTimestampParameters(contentTimestampParameters);
		TimestampToken contentTimestamp2 = service.getContentTimestamp(documentToSign, signatureParameters);

		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp, contentTimestamp2));

	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected SignedDocumentValidator getValidator(final DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
		detachedContents.add(documentToSign);
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
