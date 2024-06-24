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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.RepeatedTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS1690Test extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/Test.signed_Certipost-2048-SHA512.extended-LTA.pdf"));
	}
	
	@Override
	protected SignedDocumentValidator getValidator(final DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		CertificateVerifier offlineCertificateVerifier = getOfflineCertificateVerifier();

		// Trust cross signing certificate to get consistent result (LTA)
		CertificateSource certSource = new CommonTrustedCertificateSource();
		certSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID3jCCAsagAwIBAgILBAAAAAABBVJkxCUwDQYJKoZIhvcNAQEFBQAwXDELMAkGA1UEBhMCQkUxHDAaBgNVBAoTE0NlcnRpcG9zdCBzLmEuL24udi4xLzAtBgNVBAMTJkNlcnRpcG9zdCBFLVRydXN0IFByaW1hcnkgUXVhbGlmaWVkIENBMB4XDTA1MDcyNjEwMDAwMFoXDTIwMDcyNjEwMDAwMFowXDELMAkGA1UEBhMCQkUxHDAaBgNVBAoTE0NlcnRpcG9zdCBzLmEuL24udi4xLzAtBgNVBAMTJkNlcnRpcG9zdCBFLVRydXN0IFByaW1hcnkgUXVhbGlmaWVkIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAriDSeNuaoHKcBFIlLG1S2NcniTOg4bLV+zB1ay1/HGeODucfEt8XeRi7tBtv+D11G55nN/Dx+g917YadAwShKHAtPLJroHNR4zWpdKUIPpSFJzYqqnJk/HfudpQccuu/Msd3A2olggkFr19gPH+sG7yS6Dx0Wc7xfFQtOK6W8KxvoTMMIVoBuiMgW6CGAtVT3EkfqDKzrztGO7bvnzmzOAvneor2KPmnb1ApyHlYi0nSpdiFflbxaRV4RBE116VUPqtmJdLb4xjxLivicSMJN2RDQnQylnfel6LploacJUQJ1AGdUX4ztwlE5YCXDWRbdxiXpUupnhCdh/pWp88KfQIDAQABo4GgMIGdMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTwePkHdxC73B6hrnn7MBDbxjT4FzBIBgNVHSAEQTA/MD0GCQOQDgcBAAECADAwMC4GCCsGAQUFBwIBFiJodHRwOi8vd3d3LmUtdHJ1c3QuYmUvQ1BTL1FOY2VydHMgMBEGCWCGSAGG+EIBAQQEAwIABzANBgkqhkiG9w0BAQUFAAOCAQEAbOHYX3RY6XBJ1soNLFjaymS2UU/DBmQB6YpzHZ7PRni/O4WG4j1KGJQqgXdvgvhv9O4i/J0YIXJguxiAgpX7+feVJIFmwbXDtdK2dos7gVy4oQ4rARSLgAlA7vhgTBnkF80nAbNjEgWkCMm0v55QTrXeD5IzZnXQPecjfOolcXz+Pi42eaHlKVAjNQWVeLufeWTcV0gnLOJcM83Cu35od6cvo0kXcuEAhGt9eq85CyzV2FdkMmyECmp2OtOszZ2x5zfc7AwvxVdg34j1Q7EBZCa0J4IQsqNQ75fmf7+Rh7PbkKkq4no0bHNJ9OiNLmuK3aGKf2PQv1ger8w/klAt0Q=="));
		offlineCertificateVerifier.setTrustedCertSources(certSource);
		
		validator.setCertificateVerifier(offlineCertificateVerifier);
		validator.setSignaturePolicyProvider(getSignaturePolicyProvider());
		validator.setDetachedContents(getDetachedContents());
		return validator;
	}

	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);

		assertEquals(1, advancedSignatures.size());
		AdvancedSignature advancedSignature = advancedSignatures.get(0);

		assertEquals(2, advancedSignature.getAllTimestamps().size());
		assertEquals(2, diagnosticData.getTimestampList().size());
		
		String firstTimestampId = advancedSignature.getAllTimestamps().get(0).getDSSIdAsString();
		TimestampWrapper firstATST = diagnosticData.getTimestampById(firstTimestampId);
		assertNotNull(firstATST, "Timestamp " + firstTimestampId + " not found");
		List<TimestampWrapper> timestampedTimestamps = firstATST.getTimestampedTimestamps();
		assertEquals(0, timestampedTimestamps.size(), "First timestamp can't cover the second one");
		
		String secondTimestampId = advancedSignature.getAllTimestamps().get(1).getDSSIdAsString();
		TimestampWrapper secondATST = diagnosticData.getTimestampById(secondTimestampId);
		assertNotNull(secondATST, "Timestamp " + secondTimestampId + " not found");
		timestampedTimestamps = secondATST.getTimestampedTimestamps();
		assertEquals(1, timestampedTimestamps.size(), "Second archive timestamp must cover the first one");
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Override
	@RepeatedTest(10)
	public void validate() {
		super.validate();
	}
	
}
