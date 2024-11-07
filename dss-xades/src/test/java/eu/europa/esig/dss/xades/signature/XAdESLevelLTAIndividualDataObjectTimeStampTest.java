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
package eu.europa.esig.dss.xades.signature;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.apache.xml.security.signature.Reference;
import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.spi.x509.tsp.TimestampInclude;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.Base64Transform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;

class XAdESLevelLTAIndividualDataObjectTimeStampTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		String referenceId = "TOTO";
		String canonicalizationAlgo = CanonicalizationMethod.EXCLUSIVE;

		List<DSSTransform> transforms = new ArrayList<>();
		Base64Transform dssTransform = new Base64Transform();
		transforms.add(dssTransform);

		List<DSSReference> references = new ArrayList<>();
		DSSReference dssReference = new DSSReference();
		dssReference.setContents(documentToSign);
		dssReference.setId(referenceId);
		dssReference.setUri("#" + documentToSign.getName());
		dssReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		dssReference.setTransforms(transforms);
		dssReference.setType(Reference.OBJECT_URI);
		references.add(dssReference);

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		signatureParameters.setReferences(references);

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DSSUtils.toByteArray(documentToSign));
		TimestampBinary timeStampResponse = getAlternateGoodTsa().getTimeStampResponse(DigestAlgorithm.SHA256, digest);
		TimestampToken timestampToken = new TimestampToken(timeStampResponse.getBytes(),
				TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);
		timestampToken.setTimestampIncludes(Arrays.asList(new TimestampInclude(referenceId, true)));
		timestampToken.setCanonicalizationMethod(canonicalizationAlgo);
		signatureParameters.setContentTimestamps(Arrays.asList(timestampToken));

		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@Override
	protected SignedDocumentValidator getValidator(final DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		List<DSSDocument> detachedContents = new ArrayList<>();
		detachedContents.add(documentToSign);
		validator.setDetachedContents(detachedContents);
		return validator;
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
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

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
