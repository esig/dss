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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1401Test {

	@Test
	public void testFile1() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1401/sig_with_atsv2.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<TimestampWrapper> timestamps = signature.getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
		TimestampWrapper archiveTimestamp = timestamps.get(0);

		assertEquals(ArchiveTimestampType.CAdES_V2, archiveTimestamp.getArchiveTimestampType());
		assertTrue(archiveTimestamp.isMessageImprintDataFound());
		assertTrue(archiveTimestamp.isMessageImprintDataIntact());

	}

	@Test
	public void testFile2() {
		DSSDocument dssDocument = new FileDocument(
				"src/test/resources/validation/dss-916/test.txt.signed_Certipost-2048.detached.old.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		validator.setDetachedContents(
				Arrays.<DSSDocument>asList(new FileDocument("src/test/resources/validation/dss-916/test.txt")));
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<TimestampWrapper> timestamps = signature.getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
		
		TimestampWrapper archiveTimestamp = timestamps.get(0);
		assertTrue(archiveTimestamp.isMessageImprintDataFound());
		assertTrue(archiveTimestamp.isMessageImprintDataIntact());

	}

	@Test
	public void testFile3() {
		DSSDocument dssDocument = new FileDocument(
				"src/test/resources/validation/dss-916/test.txt.signed.qes.attached.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<TimestampWrapper> timestamps = signature.getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
		TimestampWrapper archiveTimestamp = timestamps.get(0);

		assertTrue(archiveTimestamp.isMessageImprintDataFound());
		assertTrue(archiveTimestamp.isMessageImprintDataIntact());

	}

	@Test
	public void testFile4() {
		DSSDocument dssDocument = new FileDocument(
				"src/test/resources/validation/dss-916/test.txt.signed.qes.detached.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		validator.setDetachedContents(
				Arrays.<DSSDocument>asList(new FileDocument("src/test/resources/validation/dss-916/test.txt")));
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<TimestampWrapper> timestamps = signature.getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
		TimestampWrapper archiveTimestamp = timestamps.get(0);

		assertTrue(archiveTimestamp.isMessageImprintDataFound());
		assertTrue(archiveTimestamp.isMessageImprintDataIntact());

	}

	@Test
	public void testFile5() {
		DSSDocument dssDocument = new FileDocument(
				"src/test/resources/validation/dss-1344/screenshot.png.signed_qes_detached.p7s");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		validator.setDetachedContents(
				Arrays.<DSSDocument>asList(new FileDocument("src/test/resources/validation/dss-1344/screenshot.png")));
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<TimestampWrapper> timestamps = signature.getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
		TimestampWrapper archiveTimestamp = timestamps.get(0);

		assertTrue(archiveTimestamp.isMessageImprintDataFound());
		assertTrue(archiveTimestamp.isMessageImprintDataIntact());

	}

}
