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

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelLTAWithContentTimestampsDetachedTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
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
		signerLocation.setStreetAddress("Anspach");
		signatureParameters.bLevel().setSignerLocation(signerLocation);
		signatureParameters.bLevel()
				.setCommitmentTypeIndications(Arrays.asList(CommitmentTypeEnum.ProofOfSender, CommitmentTypeEnum.ProofOfCreation));
		signatureParameters.bLevel().setClaimedSignerRoles(Arrays.asList("Manager", "Administrator"));
		signatureParameters.setAddX509SubjectName(true);

		TimestampToken contentTimestamp = service.getContentTimestamp(documentToSign, signatureParameters);
		TimestampToken contentTimestamp2 = service.getContentTimestamp(documentToSign, signatureParameters);

		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp, contentTimestamp2));

	}

	@Override
	protected SignedDocumentValidator getValidator(final DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		List<DSSDocument> detachedContents = new ArrayList<>();
		detachedContents.add(documentToSign);
		validator.setDetachedContents(detachedContents);
		return validator;
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(4, timestampList.size());
		
		TimestampWrapper contentTimestamp = timestampList.get(0);
		assertTrue(contentTimestamp.getType().isContentTimestamp());
		assertEquals(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP, contentTimestamp.getType());
		
		List<RelatedCertificateWrapper> foundCertificates = contentTimestamp.foundCertificates().getRelatedCertificates();
		List<TimestampWrapper> contentTimestamps = new ArrayList<>();
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (timestampWrapper.getType().isContentTimestamp()) {
				contentTimestamps.add(timestampWrapper);
			} else {
				List<String> certIds = timestampWrapper.getTimestampedCertificates().stream().map(CertificateWrapper::getId).collect(Collectors.toList());
				for (CertificateWrapper certificate : foundCertificates) {
					assertTrue(certIds.contains(certificate.getId()));
				}
				List<String> tstIds = timestampWrapper.getTimestampedTimestamps().stream().map(TimestampWrapper::getId).collect(Collectors.toList());
				for (TimestampWrapper contentTst : contentTimestamps) {
					assertTrue(tstIds.contains(contentTst.getId()));
				}
			}
			if (timestampWrapper.getType().isSignatureTimestamp()) {
				assertEquals(2, timestampWrapper.getTimestampedTimestamps().size());
			}
			if (timestampWrapper.getType().isArchivalTimestamp()) {
				assertEquals(3, timestampWrapper.getTimestampedTimestamps().size());
			}
		}
		assertEquals(2, contentTimestamps.size());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
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

}
