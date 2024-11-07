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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class XAdESLevelLTAInternallyDetachedMultiFilesTest extends AbstractXAdESMultipleDocumentsSignatureService {

	private XAdESService service;
	private XAdESSignatureParameters signatureParameters;
	private List<DSSDocument> documentsToSign;

	@BeforeEach
	void init() throws Exception {
		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		FileDocument f1 = new FileDocument(new File("src/test/resources/sample-with-id.xml"));
		FileDocument f2 = new FileDocument(new File("src/test/resources/sample-with-different-id.xml"));
		documentsToSign = Arrays.asList(f1, f2);

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.INTERNALLY_DETACHED);
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

		TimestampToken contentTimestamp = service.getContentTimestamp(documentsToSign, signatureParameters);
		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));
	}

	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
		assertEquals(2, signatureScopes.size());
	}

	@Override
	protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
		super.validateETSISignersDocument(signersDocument);

		DigestAlgAndValueType digestAlgoAndValue = getDigestAlgoAndValue(signersDocument);
		assertNull(digestAlgoAndValue);

		List<ValidationObjectType> validationObjects = getValidationObjects(signersDocument);
		assertEquals(2, validationObjects.size());
	}

	@Override
	protected List<DSSDocument> getDocumentsToSign() {
		return documentsToSign;
	}

	@Override
	protected MultipleDocumentsSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

}
