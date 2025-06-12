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
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.PdfObjectModificationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PAdESLevelLTATest extends AbstractPAdESTestSignature {

	private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

		service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@Override
	protected boolean isGenerateHtmlPdfReports() {
		return true;
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		String signatureId = diagnosticData.getFirstSignatureId();
		String timestampId = diagnosticData.getSignatures().get(0).getTimestampList().get(0).getId();

		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList(diagnosticData.getFirstSignatureId());
		assertEquals(2, timestampList.size());

		boolean arcTstFound = false;

		for (TimestampWrapper wrapper : timestampList) {
			boolean sigTstFound = false;
			for (SignatureWrapper signatureWrapper : wrapper.getTimestampedSignatures()) {
				if (signatureId.equals(signatureWrapper.getId())) {
					sigTstFound = true;
				}
			}
			assertTrue(sigTstFound);

			if (TimestampType.SIGNATURE_TIMESTAMP.equals(wrapper.getType())) {
				assertEquals(0, wrapper.getTimestampScopes().size());
				assertEquals(1, wrapper.getTimestampedSignedData().size());

			} else if (TimestampType.DOCUMENT_TIMESTAMP.equals(wrapper.getType())) {
				boolean coverPreviousTsp = false;
				List<TimestampWrapper> timestampedTimestamps = wrapper.getTimestampedTimestamps();
				for (TimestampWrapper timestampWrapper : timestampedTimestamps) {
					if (timestampId.equals(timestampWrapper.getId())) {
						coverPreviousTsp = true;
					}
				}
				assertTrue(coverPreviousTsp);
				assertEquals(1, wrapper.getTimestampScopes().size());
				assertEquals(2, wrapper.getTimestampedSignedData().size());

				arcTstFound = true;
			}
		}
		assertTrue(arcTstFound);
	}

	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		super.checkPdfRevision(diagnosticData);

		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());

		SignatureWrapper signatureWrapper = signatures.get(0);
		assertTrue(signatureWrapper.arePdfObjectModificationsDetected());

		assertTrue(Utils.isCollectionNotEmpty(signatureWrapper.getPdfExtensionChanges()));
		assertFalse(Utils.isCollectionNotEmpty(signatureWrapper.getPdfSignatureOrFormFillChanges()));
		assertFalse(Utils.isCollectionNotEmpty(signatureWrapper.getPdfAnnotationChanges()));
		assertFalse(Utils.isCollectionNotEmpty(signatureWrapper.getPdfUndefinedChanges()));

		boolean dssDictFound = false;
		boolean docTimeStampFound = false;
		boolean newFieldFound = false;
		List<XmlObjectModification> secureChanges = signatureWrapper.getPdfExtensionChanges();
		assertTrue(secureChanges.stream().map(XmlObjectModification::getType).collect(Collectors.toSet()).contains("DocTimeStamp"));
		for (XmlObjectModification objectModification : secureChanges) {
			assertEquals(PdfObjectModificationType.CREATION, objectModification.getAction());
			if (objectModification.getValue().contains("/DSS")) {
				dssDictFound = true;
			}
			if ("DocTimeStamp".equals(objectModification.getType())) {
				docTimeStampFound = true;
			}
			if ("Signature2".equals(objectModification.getFieldName())) {
				newFieldFound = true;
			}
		}
		assertTrue(dssDictFound);
		assertTrue(docTimeStampFound);
		assertTrue(newFieldFound);
	}

    @Override
    protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
        super.verifyDiagnosticData(diagnosticData);

        Set<SignatureWrapper> allSignatures = diagnosticData.getAllSignatures();
        for (SignatureWrapper wrapper: allSignatures) {
            assertEquals(EncryptionAlgorithm.RSA, wrapper.getEncryptionAlgorithm());
        }

        List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
        for (CertificateWrapper wrapper: usedCertificates) {
            assertEquals(EncryptionAlgorithm.RSA, wrapper.getEncryptionAlgorithm());
        }

        Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
        for (RevocationWrapper wrapper : allRevocationData) {
            assertEquals(EncryptionAlgorithm.RSA, wrapper.getEncryptionAlgorithm());
        }

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        for (TimestampWrapper wrapper : timestampList) {
			assertEquals(EncryptionAlgorithm.RSA, wrapper.getEncryptionAlgorithm());
		}
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
