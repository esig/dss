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
package eu.europa.esig.dss.asic.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

public class DSS1809Test extends AbstractASiCWithCAdESTestValidation {
	
	private static final DSSDocument document = new FileDocument("src/test/resources/validation/ASICE-CAdES-BpLTA-2-BpLTA-DSS5.4.asice");

	@Override
	protected DSSDocument getSignedDocument() {
		return document;
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(2, digestMatchers.size());
		
		boolean ASiCManifestSigned = false;
		boolean entryFound = false;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			assertNotNull(digestMatcher.getName());
			if ("META-INF/ASiCManifest.xml".equals(digestMatcher.getName())) {
				assertEquals(DigestMatcherType.MESSAGE_DIGEST, digestMatcher.getType());
				ASiCManifestSigned = true;
			} else if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
				entryFound = true;
			}
		}
		assertTrue(ASiCManifestSigned);
		assertTrue(entryFound);
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		List<XmlManifestFile> manifestFiles = diagnosticData.getContainerInfo().getManifestFiles();
		assertTrue(Utils.isCollectionNotEmpty(manifestFiles));
		assertEquals(3, manifestFiles.size());
		
		int archiveTimestampWithManifestCounter = 0;
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<TimestampWrapper> timestampList = signature.getTimestampList();
		for (TimestampWrapper timestamp : timestampList) {
			if (timestamp.getType().isArchivalTimestamp()) {
				XmlDigestMatcher messageImprint = timestamp.getMessageImprint();
				assertNotNull(messageImprint);
				assertNotNull(messageImprint.getName());
				for (XmlManifestFile manifestFile : manifestFiles) {
					if (messageImprint.getName().equals(manifestFile.getFilename())) {
						assertEquals(manifestFile.getEntries().size(), getNumberOfManifestEntries(timestamp));
						archiveTimestampWithManifestCounter++;
					}
				}
			}
		}
		assertEquals(2, archiveTimestampWithManifestCounter);
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void verifyDetailedReport(DetailedReport detailedReport) {
		super.verifyDetailedReport(detailedReport);
		
		List<String> timestampIds = detailedReport.getTimestampIds();
		
		assertNotEquals(Indication.FAILED, detailedReport.getTimestampValidationIndication(timestampIds.get(0))); // signature_timestamp
		assertEquals(Indication.FAILED, detailedReport.getTimestampValidationIndication(timestampIds.get(1))); // first archive_timestamp
		assertEquals(SubIndication.HASH_FAILURE, detailedReport.getTimestampValidationSubIndication(timestampIds.get(1))); // first archive_timestamp
		assertNotEquals(Indication.FAILED, detailedReport.getTimestampValidationIndication(timestampIds.get(2))); // second archive_timestamp
	}
	
	private int getNumberOfManifestEntries(TimestampWrapper timestampWrapper) {
		int counter = 0;
		List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
		if (Utils.isCollectionNotEmpty(digestMatchers)) {
			for (XmlDigestMatcher digestMatcher : digestMatchers) {
				if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
					counter++;
				}
			}
		}
		
		return counter;
	}

}
