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
package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.dss.validation.report.Reports;

/**
 * Unit test added to fix : https://esig-dss.atlassian.net/browse/DSS-662
 *
 */
public class CAdESWithDEREncodedTimestampTest {

	@Test
	public void testFile1() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-3.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);

		List<String> timestampIdList = diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId());
		assertTrue(CollectionUtils.isEmpty(timestampIdList));
	}

	@Test
	public void testFile2() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-4.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);

		List<String> timestampIdList = diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId());
		assertTrue(CollectionUtils.isEmpty(timestampIdList));
	}


	@Test
	public void testFile3() throws DSSException, CMSException  {
		DSSDocument dssDocument = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-4.p7m");

		CAdESSignature signature = new CAdESSignature(dssDocument.getBytes());
		CMSSignedData cmsSignedData = signature.getCmsSignedData();
		assertNotNull(cmsSignedData);
	}

}
