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
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

class ASiCERemovedReferenceTest extends AbstractASiCWithCAdESTestValidation {
	
	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/removedReference.asice");
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(3, digestMatchers.size());
		int brokenRefsCounter = 0;
		int remobedRefsCounter = 0;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (!digestMatcher.isDataIntact()) {
				brokenRefsCounter++;
			}
			if (!digestMatcher.isDataFound()) {
				remobedRefsCounter++;
			}
			assertNotNull(digestMatcher.getDigestMethod());
			assertNotNull(digestMatcher.getDigestValue());
		}
		assertEquals(1, brokenRefsCounter);
		assertEquals(1, remobedRefsCounter);
	}
	
	@Override
	protected void checkContainerInfo(DiagnosticData diagnosticData) {
		super.checkContainerInfo(diagnosticData);
		
		int manifestEntryCounter = 0;
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
				manifestEntryCounter++;
			}
		}
		
		List<XmlManifestFile> manifestFiles = diagnosticData.getContainerInfo().getManifestFiles();
		assertEquals(1, manifestFiles.size());
		List<String> entries = manifestFiles.get(0).getEntries();
		assertNotNull(entries);
		assertEquals(entries.size(), manifestEntryCounter);
	}
	
	@Override
	protected void verifyDetailedReport(DetailedReport detailedReport) {
		super.verifyDetailedReport(detailedReport);
		
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, signatureBBB.getConclusion().getSubIndication());
	}

}
