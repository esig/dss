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
package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCSWithXAdESMultiFilesValidationTest extends AbstractASiCWithXAdESTestValidation {

	private final static List<DSSDocument> EXPECTED_MULTIFILES = Arrays.asList(
			new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT),
			new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeTypeEnum.TEXT));

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/multifiles-too-much-files.asics");
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		
		assertEquals(2, signatures.size());
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		super.verifyOriginalDocuments(validator, diagnosticData);
		
		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature advancedSignature : signatures) {
			List<DSSDocument> originalDocuments = validator.getOriginalDocuments(advancedSignature.getId());
			assertEquals(2, originalDocuments.size());
			
			for (DSSDocument dssDocument : EXPECTED_MULTIFILES) {
				byte[] digestExpected = dssDocument.getDigestValue(DigestAlgorithm.SHA256);
				boolean found = false;
				for (DSSDocument retrieved : originalDocuments) {
					byte[] digestRetrieved = retrieved.getDigestValue(DigestAlgorithm.SHA256);
					if (Arrays.equals(digestExpected, digestRetrieved)) {
						found = true;
					}
				}
				assertTrue(found);
			}
		}
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		super.checkSignatureScopes(diagnosticData);
		
		List<SignatureWrapper> signatureWrappers = diagnosticData.getSignatures();
		for (SignatureWrapper signature : signatureWrappers) {
			assertNotNull(signature);
			List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
			assertNotNull(signatureScopes);
			assertEquals(3, signatureScopes.size());
			int archivedFiles = 0;
			for (XmlSignatureScope signatureScope : signatureScopes) {
				if (SignatureScopeType.ARCHIVED.equals(signatureScope.getScope())) {
					archivedFiles++;
				}
			}
			assertEquals(2, archivedFiles);
		}
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);
		
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Override
	protected void verifyDetailedReport(DetailedReport detailedReport) {
		super.verifyDetailedReport(detailedReport);
		
		XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(bbb);
		
		XmlFC fc = bbb.getFC();
		assertNotNull(fc);
		assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());
		
		for (XmlConstraint xmlConstraint : fc.getConstraint()) {
			if (MessageTag.BBB_FC_ISFP_ASICS.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				assertEquals(MessageTag.BBB_FC_ISFP_ASICS_ANS.getId(), xmlConstraint.getError().getKey());
			} else {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
			}
		}
	}

}
