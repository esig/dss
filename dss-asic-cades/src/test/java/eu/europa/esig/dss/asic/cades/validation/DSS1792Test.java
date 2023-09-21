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

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestParser;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.ASiCManifestTypeEnum;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ManifestFile;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class DSS1792Test extends AbstractASiCWithCAdESTestValidation {
	
	private static final DSSDocument document = new FileDocument("src/test/resources/validation/dss1792.asice");

	@Override
	protected DSSDocument getSignedDocument() {
		return document;
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		assertEquals(2, diagnosticData.getTimestampList().size());
		boolean archiveTimestampFound = false;
		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			if (timestamp.getType().isContainerTimestamp()) {
				assertEquals(ArchiveTimestampType.CAdES_DETACHED, timestamp.getArchiveTimestampType());
				archiveTimestampFound = true;
			}
		}
		assertTrue(archiveTimestampFound);
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);
		
		List<SignatureWrapper> signatureWrappers = diagnosticData.getSignatures();
		assertEquals(2, signatureWrappers.size());
		
		for (SignatureWrapper signature : signatureWrappers) {
			List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
			assertNotNull(digestMatchers);
			for (XmlDigestMatcher digestMatcher : digestMatchers) {
				assertTrue(digestMatcher.isDataFound());
				assertTrue(digestMatcher.isDataIntact());
			}
			if ("META-INF/signature001.p7s".equals(signature.getSignatureFilename())) {
				assertEquals(3, digestMatchers.size());
			} else if ("META-INF/signature002.p7s".equals(signature.getSignatureFilename())) {
				assertEquals(7, digestMatchers.size());
			} else {
    			fail("Unexpected signature found with name : " + signature.getSignatureFilename());
			}
		}
	}
	
	@Test
	public void manifestExtractorTest() {
		
        AbstractASiCContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(document);
        ASiCContent result = extractor.extract();
        
        List<DSSDocument> manifestFiles = result.getManifestDocuments();
        assertEquals(3, manifestFiles.size());
        
        List<DSSDocument> archiveManifestFiles = result.getArchiveManifestDocuments();
        assertEquals(0, archiveManifestFiles.size());
        
        List<DSSDocument> allManifestFiles = result.getAllManifestDocuments();
        assertEquals(3, allManifestFiles.size());
        
        for (DSSDocument manifest : allManifestFiles) {
        	ManifestFile manifestFile = ASiCManifestParser.getManifestFile(manifest);
			assertNotNull(manifestFile);
        	switch (manifestFile.getFilename()) {
        		case "META-INF/ASiCManifest.xml":
        			assertEquals("META-INF/signature001.p7s", manifestFile.getSignatureFilename());
					assertEquals(ASiCManifestTypeEnum.SIGNATURE, manifestFile.getManifestType());
        			break;
        		case "META-INF/ASiCManifest1.xml":
        			assertEquals("META-INF/timestamp001.tst", manifestFile.getSignatureFilename());
					assertEquals(ASiCManifestTypeEnum.TIMESTAMP, manifestFile.getManifestType());
        			break;
        		case "META-INF/ASiCManifest2.xml":
        			assertEquals("META-INF/signature002.p7s", manifestFile.getSignatureFilename());
					assertEquals(ASiCManifestTypeEnum.SIGNATURE, manifestFile.getManifestType());
        			break;
        		default:
        			fail("Unexpected manifest found with name : " + manifestFile.getFilename());
        	}
        }
        
        assertEquals(2, result.getSignedDocuments().size());
		
	}

}
