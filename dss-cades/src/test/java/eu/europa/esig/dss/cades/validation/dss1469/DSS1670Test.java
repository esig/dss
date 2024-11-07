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
package eu.europa.esig.dss.cades.validation.dss1469;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.cades.validation.AbstractCAdESTestValidation;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAbstractToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

class DSS1670Test extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss-1670/signatureExtendedTwoLTA.p7s");
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Arrays.asList(new FileDocument("src/test/resources/validation/dss-1670/screenshot.png"));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		List<TimestampWrapper> timestampList = signature.getTimestampList();
		assertNotNull(timestampList);
		assertEquals(3, timestampList.size());
		
		int timestamedTimestampsCounter = 0;
		for (TimestampWrapper timestamp : timestampList) {			
			List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
			assertNotNull(timestampedObjects);
			assertTrue(timestampedObjects.size() > 0);
			
			for (XmlTimestampedObject timestampedObject : timestampedObjects) {
				XmlAbstractToken token = timestampedObject.getToken();
				if (token instanceof XmlTimestamp) {
					XmlTimestamp timestampedTimestamp = (XmlTimestamp) token;
					assertNotNull(timestampedTimestamp);
					assertTrue(timestampedTimestamp.getProductionTime().before(timestamp.getProductionTime()));
					timestamedTimestampsCounter++;
				}
			}
		}
		assertEquals(3, timestamedTimestampsCounter);
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertEquals(SignatureLevel.CAdES_C, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isSigningCertificateIdentified());
		assertTrue(signature.isSigningCertificateReferencePresent());
		assertFalse(signature.isSigningCertificateReferenceUnique());
		
		CertificateRefWrapper signingCertificateReference = signature.getSigningCertificateReference();
		assertNotNull(signingCertificateReference);
		assertTrue(signingCertificateReference.isDigestValuePresent());
		assertTrue(signingCertificateReference.isDigestValueMatch());
		assertTrue(signingCertificateReference.isIssuerSerialPresent());
		assertTrue(signingCertificateReference.isIssuerSerialMatch());
	}

}
