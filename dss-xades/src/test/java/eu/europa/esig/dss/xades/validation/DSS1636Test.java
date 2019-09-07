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
package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1636Test extends PKIFactoryAccess {
	
	@Test
	public void dss1636WithContentTimestampTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1636/detached_cts.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		DetailedReport detailedReport = reports.getDetailedReport();
		List<String> timestampIds = diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId());
		assertEquals(1, timestampIds.size());
		String timestampId = timestampIds.iterator().next();
		Indication indication = detailedReport.getBasicBuildingBlocksIndication(timestampId);
		assertEquals(Indication.INDETERMINATE, indication);
		SubIndication subIndication = detailedReport.getBasicBuildingBlocksSubIndication(timestampId);
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, subIndication);
	}
	
	@Test
	public void dss1636WithContentTimestampAndIncorrectDataTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1636/detached_cts.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setDetachedContents(Arrays.<DSSDocument>asList(new InMemoryDocument(new byte[] { 1, 2, 3 })));
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		DetailedReport detailedReport = reports.getDetailedReport();
		List<String> timestampIds = diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId());
		assertEquals(1, timestampIds.size());
		String timestampId = timestampIds.iterator().next();
		Indication indication = detailedReport.getBasicBuildingBlocksIndication(timestampId);
		assertEquals(Indication.FAILED, indication);
		SubIndication subIndication = detailedReport.getBasicBuildingBlocksSubIndication(timestampId);
		assertEquals(SubIndication.HASH_FAILURE, subIndication);
	}

	@Test
	public void dss1636WithoutContentTimestampTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1636/detached_no_cts.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
