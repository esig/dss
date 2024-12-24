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
package eu.europa.esig.dss.asic.cades.signature.asics;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCSCAdESLevelBMultiFilesTest extends AbstractASiCSWithCAdESMultipleDocumentsTestSignature {

	private ASiCWithCAdESService service;
	private ASiCWithCAdESSignatureParameters signatureParameters;
	private List<DSSDocument> documentsToSign = new ArrayList<>();

	@BeforeEach
	void init() throws Exception {
		service = new ASiCWithCAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		documentsToSign.add(new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT));
		documentsToSign.add(new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeTypeEnum.TEXT));
		documentsToSign.add(new InMemoryDocument(DSSUtils.EMPTY_BYTE_ARRAY, "emptyByteArray"));

		signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

		TimestampToken contentTimestamp = service.getContentTimestamp(documentsToSign, signatureParameters);
		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));
	}

	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		super.checkSignatureScopes(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		assertEquals(4, Utils.collectionSize(signatureScopes)); // package.zip + three signed files
		int archive = 0;
		int archiveContent = 0;
		for (XmlSignatureScope signatureScope : signatureScopes) {
			if ("package.zip".equals(signatureScope.getName()) && SignatureScopeType.FULL.equals(signatureScope.getScope())) {
				archive++;
			}
			if (SignatureScopeType.ARCHIVED.equals(signatureScope.getScope())) {
				archiveContent++;
			}
		}
		assertEquals(1, archive);
		assertEquals(3, archiveContent);
	}

	@Override
	protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
		super.validateETSISignersDocument(signersDocument);

		DigestAlgAndValueType digestAlgoAndValue = getDigestAlgoAndValue(signersDocument);
		assertNotNull(digestAlgoAndValue);
		assertNotNull(digestAlgoAndValue.getDigestMethod());
		assertNotNull(digestAlgoAndValue.getDigestValue());

		List<ValidationObjectType> validationObjects = getValidationObjects(signersDocument);
		assertEquals(4, validationObjects.size());
	}

	@Override
	protected void checkMimeType(DiagnosticData diagnosticData) {
		super.checkMimeType(diagnosticData);

		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertEquals(MimeTypeEnum.ZIP, MimeType.fromMimeTypeString(signatureWrapper.getMimeType())); // package.zip signed
		}
	}

	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<DSSDocument> retrievedDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
		for (DSSDocument document : documentsToSign) {
			boolean found = false;
			for (DSSDocument retrievedDoc : retrievedDocuments) {
				if (Arrays.equals(DSSUtils.toByteArray(document), DSSUtils.toByteArray(retrievedDoc))) {
					found = true;
				}
			}
			assertTrue(found);
		}
	}

	@Override
	protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected List<DSSDocument> getDocumentsToSign() {
		return documentsToSign;
	}

	@Override
	protected MultipleDocumentsSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
