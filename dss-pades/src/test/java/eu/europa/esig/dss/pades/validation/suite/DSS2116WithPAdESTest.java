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
package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;

class DSS2116WithPAdESTest extends AbstractPAdESTestValidation {

	private static final DigestAlgorithm ORIGINAL_DA = DigestAlgorithm.SHA256;
	private static final String ORIGINAL_DTBSR = "Zym/kv++RGKZ7eDCjvxQwUFBzvU1XiHFj+nwMUcNuMQ=";

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/Signature-P-HU_MIC-1.pdf"));
	}
	
	@Override
	protected void checkDTBSR(DiagnosticData diagnosticData) {
		super.checkDTBSR(diagnosticData);
		
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		XmlDigestAlgoAndValue dataToBeSignedRepresentation = signatureWrapper.getDataToBeSignedRepresentation();
		assertEquals(ORIGINAL_DA, dataToBeSignedRepresentation.getDigestMethod());
		assertEquals(ORIGINAL_DTBSR, Utils.toBase64(dataToBeSignedRepresentation.getDigestValue()));
	}
	
	@Override
	protected void validateETSISignatureIdentifier(SignatureIdentifierType signatureIdentifier) {
		super.validateETSISignatureIdentifier(signatureIdentifier);

		assertEquals(ORIGINAL_DA, DigestAlgorithm.forXML(signatureIdentifier.getDigestAlgAndValue().getDigestMethod().getAlgorithm()));
		assertEquals(ORIGINAL_DTBSR, Utils.toBase64(signatureIdentifier.getDigestAlgAndValue().getDigestValue()));
	}

}
