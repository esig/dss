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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignatureScopeType;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Test for XML Signature wrapping detection
 */
public class XMLSignatureWrappingTest {

	@Test
	public void testEnvelopedFakeSignedProperties() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/XSW-enveloped-fake-signedProperties.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		CertificateToken rootToken = DSSUtils.loadCertificateFromBase64EncodedString(
				"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");
		checkForTrustedCertificateRoot(validator, certificateVerifier, rootToken);
	}

	@Test
	public void testEnvelopedOriginal() {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/original.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());
		assertTrue(signatureById.isSignatureValid());
	}

	@Test
	public void testEnvelopedFakeContent() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/XSW-enveloped-fake-content.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());
		assertTrue(signatureById.isSignatureValid());

		List<XmlSignatureScope> signatureScopes = signatureById.getSignatureScopes();
		assertEquals(1, signatureScopes.size());
		assertEquals(SignatureScopeType.PARTIAL, signatureScopes.get(0).getScope());
	}

	@Test
	public void testCY() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/TSL-CY-sign.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());
		assertTrue(signatureById.isSignatureValid());

		List<XmlSignatureScope> signatureScopes = signatureById.getSignatureScopes();
		assertEquals(1, signatureScopes.size());
		assertEquals(SignatureScopeType.FULL, signatureScopes.get(0).getScope());
	}

	@Test
	public void testNoId() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/TSL-noID.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());
		assertTrue(signatureById.isSignatureValid());

		List<XmlSignatureScope> signatureScopes = signatureById.getSignatureScopes();
		assertEquals(1, signatureScopes.size());
		assertEquals(SignatureScopeType.FULL, signatureScopes.get(0).getScope());
	}

	@Test
	public void testEnvelopedFakeContentMisplaced() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/XSW-enveloped-fake-content-misplaced.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());
		assertTrue(signatureById.isSignatureValid());

		List<XmlSignatureScope> signatureScopes = signatureById.getSignatureScopes();
		assertEquals(1, signatureScopes.size());
		assertEquals(SignatureScopeType.PARTIAL, signatureScopes.get(0).getScope());
	}

	@Test
	public void testEnvelopedFakeContentTwoSameIds() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/XSW-enveloped-fake-content-two-same-id.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		CertificateToken rootToken = DSSUtils.loadCertificateFromBase64EncodedString(
				"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");
				checkForTrustedCertificateRoot(validator, certificateVerifier, rootToken);
	}

	@Test
	public void testEnvelopingFakeObject() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/XSW-enveloping-fake-object.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		CertificateToken rootToken = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID1DCCArygAwIBAgIBCjANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTcwOTI5MDg1NzMyWhcNMTkwNzI5MDg1NzMyWjBPMRIwEAYDVQQDDAlnb29kLXVzZXIxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJiJTCR/uqNZPWXpToBIOrH1ggpmmZ4Lq4aSkxPhkHTNacI59Va3WyCnrIRN3EgJraLJ+dp7CD/5wbh9Utu7UHG5vs2ZTifPIdsWf3551BWQzi4ksYJO390/9H0H3G/MSabI3rairYvHdkSdQF7/3PImT1k5PyREiJ/VrhYbLRaeSaF1rpAznzHfp3+MWGbjtJe7DBvuxu+Ob38I3Z4+hcGwxmqoioT3yF4vieahPmSHtv2sDrK3IiL5v2YTzleKA4k3+0J2gSQia8KCKECjsKKFsRYefCDM6YPpjs49/51ppV5YwA1GKbl9UtGh6bPwiypiT7FvpiGTBPa+TRJktw0CAwEAAaOBvDCBuTAOBgNVHQ8BAf8EBAMCBkAwgYcGCCsGAQUFBwEBBHsweTA5BggrBgEFBQcwAYYtaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3Rvcnkvb2NzcC9nb29kLWNhMDwGCCsGAQUFBzAChjBodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvZ29vZC1jYS5jcnQwHQYDVR0OBBYEFF6/dyhxBXMAMXBN7889SSzNgGvxMA0GCSqGSIb3DQEBCwUAA4IBAQCb9an2uzczD2dkyHMeZ9YI4cki9YOJ+3isdxdZG6ErlTvTb31zhOdQZOxhA9EpCwyG/It0nMTImJoUDJumixD0ZH/pyb0DeXyCgZbOVB4txxTKksRNbMvD6gKnIekJlfQEJnPIteyqp4EMZdcIZ105ud5lQ3c2Illl4FMjLkz+6QDI+8sN2hnVP43hImFwJfxng+pZeteD0Bhb0x7MD+jf9CL+1Ty0S7ZEoAgSlRKztJtoWfoFOxd+pepfYFlit7/muuqOLNdzj9P6zK4KAF6xM/ulHa77cHwroxpRYL9bhCZTk7sZGtWSfJZfvRH+shMzh4PPJGMAcsbDeVtpXvFZ");
		checkForTrustedCertificateRoot(validator, certificateVerifier, rootToken);
	}

	@Test
	public void testEnvelopingFakeManifest() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xsw/XSW-enveloping-fake-manifest.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		CertificateToken rootToken = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID1DCCArygAwIBAgIBCjANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTcwOTI5MDg1NzMyWhcNMTkwNzI5MDg1NzMyWjBPMRIwEAYDVQQDDAlnb29kLXVzZXIxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJiJTCR/uqNZPWXpToBIOrH1ggpmmZ4Lq4aSkxPhkHTNacI59Va3WyCnrIRN3EgJraLJ+dp7CD/5wbh9Utu7UHG5vs2ZTifPIdsWf3551BWQzi4ksYJO390/9H0H3G/MSabI3rairYvHdkSdQF7/3PImT1k5PyREiJ/VrhYbLRaeSaF1rpAznzHfp3+MWGbjtJe7DBvuxu+Ob38I3Z4+hcGwxmqoioT3yF4vieahPmSHtv2sDrK3IiL5v2YTzleKA4k3+0J2gSQia8KCKECjsKKFsRYefCDM6YPpjs49/51ppV5YwA1GKbl9UtGh6bPwiypiT7FvpiGTBPa+TRJktw0CAwEAAaOBvDCBuTAOBgNVHQ8BAf8EBAMCBkAwgYcGCCsGAQUFBwEBBHsweTA5BggrBgEFBQcwAYYtaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3Rvcnkvb2NzcC9nb29kLWNhMDwGCCsGAQUFBzAChjBodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvZ29vZC1jYS5jcnQwHQYDVR0OBBYEFF6/dyhxBXMAMXBN7889SSzNgGvxMA0GCSqGSIb3DQEBCwUAA4IBAQCb9an2uzczD2dkyHMeZ9YI4cki9YOJ+3isdxdZG6ErlTvTb31zhOdQZOxhA9EpCwyG/It0nMTImJoUDJumixD0ZH/pyb0DeXyCgZbOVB4txxTKksRNbMvD6gKnIekJlfQEJnPIteyqp4EMZdcIZ105ud5lQ3c2Illl4FMjLkz+6QDI+8sN2hnVP43hImFwJfxng+pZeteD0Bhb0x7MD+jf9CL+1Ty0S7ZEoAgSlRKztJtoWfoFOxd+pepfYFlit7/muuqOLNdzj9P6zK4KAF6xM/ulHa77cHwroxpRYL9bhCZTk7sZGtWSfJZfvRH+shMzh4PPJGMAcsbDeVtpXvFZ");
		checkForTrustedCertificateRoot(validator, certificateVerifier, rootToken);
	}
	
	/**
	 * Test added to ensure passing in case of trusted certificates/roots due to reorder of Basic Signature Validation according to EN 319 102-1 v1.1.1
	 */
	private void checkForTrustedCertificateRoot(SignedDocumentValidator validator, CommonCertificateVerifier certificateVerifier, CertificateToken rootToken) {

		TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();
		trustedListsCertificateSource.addCertificate(rootToken, Arrays.asList(new ServiceInfo()));

		certificateVerifier.setTrustedCertSource(trustedListsCertificateSource);
		validator.setCertificateVerifier(certificateVerifier);
		
		Reports reports = validator.validateDocument();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
	}

}
