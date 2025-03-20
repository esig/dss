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
package eu.europa.esig.dss.pades.validation.suite.dss1899;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS1899TstWithNullTypeTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-tst-with-null-type.pdf"));
	}
	
	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		super.checkNumberOfSignatures(diagnosticData);
		
		assertEquals(1, diagnosticData.getSignatures().size());
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		super.checkSignatureLevel(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(SignatureLevel.PAdES_BASELINE_LTA, signature.getSignatureFormat());
	}
	
	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		assertNotNull(signature.getFirstFieldName());
		assertTrue(Utils.isCollectionNotEmpty(signature.getSignatureFieldNames()));
		assertEquals(1, signature.getSignatureFieldNames().size());
		assertNotNull(signature.getSignatureDictionaryType());
		assertNotNull(signature.getFilter());
		assertNotNull(signature.getSubFilter());
		assertNotNull(signature.getSignatureByteRange());
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		TimestampWrapper docTimestamp = null;
		for (TimestampWrapper timestamp : timestampList) {
			if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestamp.getType())) {
				docTimestamp = timestamp;
			}
		}
		
		assertNotNull(docTimestamp);
		assertNull(docTimestamp.getSignatureDictionaryType());
		assertTrue(Utils.isCollectionNotEmpty(docTimestamp.getSignatureFieldNames()));
		assertTrue(Utils.isCollectionNotEmpty(docTimestamp.getSignatureByteRange()));
		assertNotNull(docTimestamp.getFilter());
		assertNotNull(docTimestamp.getSubFilter());
	}

}
