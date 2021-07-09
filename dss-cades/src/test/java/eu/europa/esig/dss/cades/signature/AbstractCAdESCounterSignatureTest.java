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
package eu.europa.esig.dss.cades.signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.test.signature.AbstractCounterSignatureTest;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public abstract class AbstractCAdESCounterSignatureTest
		extends AbstractCounterSignatureTest<CAdESSignatureParameters, CAdESTimestampParameters, CAdESCounterSignatureParameters> {

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.PKCS7;
	}

	@Override
	protected boolean isBaselineT() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.CAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.CAdES_BASELINE_LT.equals(signatureLevel)
				|| SignatureLevel.CAdES_BASELINE_T.equals(signatureLevel);
	}

	@Override
	protected boolean isBaselineLTA() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.CAdES_BASELINE_LTA.equals(signatureLevel);
	}

	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertNotNull(signatureWrapper.getSignatureValue());
		}
	}

	@Override
	protected void checkReportsSignatureIdentifier(Reports reports) {
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		for (SignatureValidationReportType signatureValidationReport : etsiValidationReport.getSignatureValidationReport()) {
			SignatureWrapper signature = diagnosticData.getSignatureById(signatureValidationReport.getSignatureIdentifier().getId());

			SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
			assertNotNull(signatureIdentifier);

			assertNotNull(signatureIdentifier.getSignatureValue());
            assertArrayEquals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue());
		}
	}

	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		for (String signatureId : signatureIdList) {

			List<DSSDocument> retrievedOriginalDocuments = validator.getOriginalDocuments(signatureId);
			assertTrue(Utils.isCollectionNotEmpty(retrievedOriginalDocuments));

			SignatureWrapper signature = diagnosticData.getSignatureById(signatureId);
			if (signature.isCounterSignature()) {
				continue;
			}

			List<DSSDocument> originalDocuments = getOriginalDocuments();
			for (DSSDocument original : originalDocuments) {
				boolean found = false;

				String originalDigest = original.getDigest(DigestAlgorithm.SHA256);
				for (DSSDocument retrieved : retrievedOriginalDocuments) {
					String retrievedDigest = retrieved.getDigest(DigestAlgorithm.SHA256);
					if (Utils.areStringsEqual(originalDigest, retrievedDigest)) {
						found = true;
					}
				}

				assertTrue(found);
			}
		}
	}

}