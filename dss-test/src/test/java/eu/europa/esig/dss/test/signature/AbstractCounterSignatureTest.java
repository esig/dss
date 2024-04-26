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
package eu.europa.esig.dss.test.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableCounterSignatureParameters;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.validationreport.jaxb.SACounterSignatureType;
import eu.europa.esig.validationreport.jaxb.SignatureAttributesType;
import eu.europa.esig.validationreport.jaxb.VOReferenceType;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.xml.bind.JAXBElement;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractCounterSignatureTest<SP extends SerializableSignatureParameters, TP extends SerializableTimestampParameters, 
				CSP extends SerializableCounterSignatureParameters> extends AbstractPkiFactoryTestDocumentSignatureService<SP, TP> {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractCounterSignatureTest.class);
	
	protected abstract CSP getCounterSignatureParameters();

	protected abstract CounterSignatureService<CSP> getCounterSignatureService();
	
	private String signatureId;
	
	@Override
	@Test
	public void signAndVerify() {
		final DSSDocument signedDocument = sign();

		// signedDocument.save("target/signed-" + signedDocument.getName());

		SignedDocumentValidator validator = getValidator(signedDocument);

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertTrue(Utils.isCollectionNotEmpty(signatures));
		
		AdvancedSignature signature = signatures.get(signatures.size() - 1);
		signatureId = signature.getId();
		
		DSSDocument counterSigned = counterSign(signedDocument, getSignatureIdToCounterSign());

		assertNotNull(counterSigned.getName());
		assertNotNull(DSSUtils.toByteArray(counterSigned));
		assertNotNull(counterSigned.getMimeType());

		// counterSigned.save("target/counter-signed-" + counterSigned.getName());

		byte[] byteArray = DSSUtils.toByteArray(counterSigned);
		onDocumentSigned(byteArray);
		if (LOG.isDebugEnabled()) {
			LOG.debug(new String(byteArray));
		}

		checkMimeType(counterSigned);

		validator = getValidator(counterSigned);
		List<AdvancedSignature> signatures2 = validator.getSignatures();

		for (AdvancedSignature sig : signatures) {
			boolean found = false;
			for (AdvancedSignature sig2 : signatures2) {
				if (Utils.areStringsEqual(sig.getId(), sig2.getId())) {
					found = true;
					break;
				}
			}
			assertTrue(found, String.format("Signature IDs have changed (before : %s / after : %s", signatures, signatures2));
		}
		
		verify(counterSigned);
	}
	
	protected DSSDocument counterSign(DSSDocument signatureDocument, String signatureId) {
		CSP counterSignatureParameters = getCounterSignatureParameters();
		counterSignatureParameters.setSignatureIdToCounterSign(signatureId);
		
		CounterSignatureService<CSP> counterSignatureService = getCounterSignatureService();
		
		ToBeSigned dataToSign = counterSignatureService.getDataToBeCounterSigned(signatureDocument, counterSignatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, counterSignatureParameters.getSignatureAlgorithm(), getPrivateKeyEntry());
		return counterSignatureService.counterSignSignature(signatureDocument, counterSignatureParameters, signatureValue);
	}

	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		assertEquals(2, Utils.collectionSize(diagnosticData.getSignatureIdList()));
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		
		String counterSignedSignatureId = getSignatureIdToCounterSign();
		
		boolean counterSignatureFound = false;
		for (AdvancedSignature signature : signatures) {
			if (counterSignedSignatureId.equals(signature.getId()) || counterSignedSignatureId.equals(signature.getDAIdentifier())) {
				List<AdvancedSignature> counterSignatures = signature.getCounterSignatures();
				assertTrue(Utils.isCollectionNotEmpty(signature.getCounterSignatures()));
				for (AdvancedSignature counterSignature : counterSignatures) {
					AdvancedSignature masterSignature = counterSignature.getMasterSignature();
					assertNotNull(masterSignature);
					assertTrue(counterSignedSignatureId.equals(masterSignature.getId()) || 
							counterSignedSignatureId.equals(masterSignature.getDAIdentifier()));
					counterSignatureFound = true;
				}
			}
		}
		assertTrue(counterSignatureFound);
	}
	
	@Override
	protected void validateETSISignatureAttributes(SignatureAttributesType signatureAttributes) {
		SerializableSignatureParameters signatureParameters = hasCounterSignature(signatureAttributes) ? 
				getSignatureParameters() : getCounterSignatureParameters();
		super.validateETSISignatureAttributes(signatureAttributes, signatureParameters);
	}

	protected boolean hasCounterSignature(SignatureAttributesType signatureAttributes) {
		List<JAXBElement<?>> signatureAttributeObjects = signatureAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat();
		for (JAXBElement<?> signatureAttributeObj : signatureAttributeObjects) {
			Object value = signatureAttributeObj.getValue();
			if (value instanceof SACounterSignatureType) {
				// TODO multiple value -> multiple tag in signatureattributes ??
				SACounterSignatureType counterSignature = (SACounterSignatureType) value;
				List<VOReferenceType> attributeObject = counterSignature.getAttributeObject();
				assertTrue(Utils.isCollectionNotEmpty(attributeObject));
				assertNotNull(counterSignature.getCounterSignature());
				assertNotNull(counterSignature.getCounterSignature().getDigestMethod());
				assertNotNull(counterSignature.getCounterSignature().getDigestValue());

				return true;
			}
		}
		return false;
	}

	protected String getSignatureIdToCounterSign() {
		return signatureId;
	}

}
