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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import javax.xml.bind.JAXBElement;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.OrphanTokenType;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlAbstractToken;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateRef;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.jaxb.diagnostic.XmlFoundCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOrphanCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOrphanRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOrphanToken;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRelatedCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocationRef;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureDigestReference;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignerData;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedObject;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XPathQueryHolder;
import eu.europa.esig.jaxb.validationreport.POEProvisioningType;
import eu.europa.esig.jaxb.validationreport.SASigPolicyIdentifierType;
import eu.europa.esig.jaxb.validationreport.SignatureIdentifierType;
import eu.europa.esig.jaxb.validationreport.SignatureReferenceType;
import eu.europa.esig.jaxb.validationreport.SignatureValidationReportType;
import eu.europa.esig.jaxb.validationreport.ValidationObjectListType;
import eu.europa.esig.jaxb.validationreport.ValidationObjectType;
import eu.europa.esig.jaxb.validationreport.ValidationReportType;
import eu.europa.esig.jaxb.validationreport.enums.ObjectType;

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
		
		FileDocument document = new FileDocument(new File("src/test/resources/validation/xsw/original.xml"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());
		assertTrue(signatureById.isSignatureValid());
		
		XmlSignatureDigestReference signatureDigestReference = signatureById.getSignatureDigestReference();
		assertNotNull(signatureDigestReference);

		XPathQueryHolder xPathQueryHolder = new XPathQueryHolder();
		Document documentDom = DomUtils.buildDOM(document);
		NodeList nodeList = DomUtils.getNodeList(documentDom.getDocumentElement(), xPathQueryHolder.XPATH__SIGNATURE);
		Element signatureElement = (Element) nodeList.item(0);
		byte[] canonicalizedSignatureElement = DSSXMLUtils.canonicalizeSubtree(signatureDigestReference.getCanonicalizationMethod(), signatureElement);
		byte[] digest = DSSUtils.digest(signatureDigestReference.getDigestMethod(), canonicalizedSignatureElement);
		
		String signatureReferenceDigestValue = Utils.toBase64(signatureDigestReference.getDigestValue());
		String signatureElementDigestValue = Utils.toBase64(digest);
		assertEquals(signatureReferenceDigestValue, signatureElementDigestValue);
		
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
	
	@Test
	public void signaturePolicyIdentifierTest() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/valid-xades.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		assertNotNull(signature.getPolicyId());
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationReport);
		assertNotNull(signatureValidationReport.getSignatureAttributes());
		List<Object> signingTimeOrSigningCertificateOrDataObjectFormat = signatureValidationReport.getSignatureAttributes().getSigningTimeOrSigningCertificateOrDataObjectFormat();
		assertNotNull(signingTimeOrSigningCertificateOrDataObjectFormat);
		boolean signaturePolicyIdPresent = false;
		for (Object object : signingTimeOrSigningCertificateOrDataObjectFormat) {
			JAXBElement<?> jaxbElement = (JAXBElement<?>) object;
			if (jaxbElement.getValue() instanceof SASigPolicyIdentifierType) {
				SASigPolicyIdentifierType sigPolicyIdentifier = (SASigPolicyIdentifierType) jaxbElement.getValue();
				assertNotNull(sigPolicyIdentifier);
				assertEquals(signature.getPolicyId(), sigPolicyIdentifier.getSigPolicyId());
				signaturePolicyIdPresent = true;
			}
		}
		assertTrue(signaturePolicyIdPresent);
		
	}
	
	@Test
	public void signatureIdentifierTest() {
		
		FileDocument document = new FileDocument(new File("src/test/resources/validation/valid-xades.xml"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		assertNotNull(signature.getSignatureValue());
		assertNotNull(signature.getDAIdentifier());
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationReport);
		SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
		assertNotNull(signatureIdentifier);
		assertFalse(signatureIdentifier.isDocHashOnly());
		assertFalse(signatureIdentifier.isHashOnly());
		
		assertNotNull(signatureIdentifier.getSignatureValue());
		assertTrue(Arrays.equals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue()));
		assertNotNull(signatureIdentifier.getDAIdentifier());
		assertEquals(signature.getDAIdentifier(), signatureIdentifier.getDAIdentifier());
		
		XmlSignatureDigestReference signatureDigestReference = signature.getSignatureDigestReference();
		assertNotNull(signatureDigestReference);

		XPathQueryHolder xPathQueryHolder = new XPathQueryHolder();
		Document documentDom = DomUtils.buildDOM(document);
		NodeList nodeList = DomUtils.getNodeList(documentDom, xPathQueryHolder.XPATH__SIGNATURE);
		assertEquals(1, nodeList.getLength());
		Element signatureElement = (Element) nodeList.item(0);
		byte[] canonicalizedSignatureElement = DSSXMLUtils.canonicalizeSubtree(signatureDigestReference.getCanonicalizationMethod(), signatureElement);
		byte[] digest = DSSUtils.digest(signatureDigestReference.getDigestMethod(), canonicalizedSignatureElement);
		
		String signatureReferenceDigestValue = Utils.toBase64(signatureDigestReference.getDigestValue());
		String signatureElementDigestValue = Utils.toBase64(digest);
		assertEquals(signatureReferenceDigestValue, signatureElementDigestValue);
		
	}
	
	@Test
	public void noSignedDataSignatureTest() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/dss-signed-altered-signedPropsRemoved.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);
		
		Reports reports = validator.validateDocument();
		//reports.print();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertNotNull(digestMatchers);
		boolean signedPropertiesMatcherFound = false;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestMatcherType.SIGNED_PROPERTIES.equals(digestMatcher.getType())) {
				signedPropertiesMatcherFound = true;
			}
		}
		assertFalse(signedPropertiesMatcherFound);
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationReport);
		SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
		assertNotNull(signatureIdentifier);
		assertNotNull(signatureIdentifier.getDigestAlgAndValue());
		
	}
	
	@Test
	public void signatureScopeTest() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/valid-xades.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);
		
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<XmlSignerData> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		assertNotNull(originalSignerDocuments);
		assertEquals(1, originalSignerDocuments.size());
		XmlSignerData xmlSignerData = originalSignerDocuments.get(0);
		assertNotNull(xmlSignerData.getId());
		
		assertEquals(1, diagnosticData.getSignatures().size());
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		assertNotNull(signatureScopes);
		assertEquals(1, signatureScopes.size());
		XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
		assertNotNull(xmlSignatureScope.getName());
		assertNotNull(xmlSignatureScope.getDescription());
		assertNotNull(xmlSignatureScope.getScope());
		assertEquals(SignatureScopeType.PARTIAL, xmlSignatureScope.getScope());
		assertNotNull(xmlSignatureScope.getSignerData());
		assertNotNull(xmlSignatureScope.getSignerData().getId());
		assertEquals(xmlSignerData.getId(), xmlSignatureScope.getSignerData().getId());
		assertNotNull(xmlSignatureScope.getSignerData().getReferencedName());
		assertNotNull(xmlSignatureScope.getSignerData().getDigestAlgoAndValue());
		assertNotNull(xmlSignatureScope.getSignerData().getDigestAlgoAndValue().getDigestMethod());
		assertNotNull(xmlSignatureScope.getSignerData().getDigestAlgoAndValue().getDigestValue());
		assertNotNull(xmlSignatureScope.getTransformations());
		assertEquals(1, xmlSignatureScope.getTransformations().size());
		
		ValidationReportType etsiValidationReportJaxb = reports.getEtsiValidationReportJaxb();
		ValidationObjectListType signatureValidationObjects = etsiValidationReportJaxb.getSignatureValidationObjects();
		int expectedSignedDataObjects = 0;
		for (ValidationObjectType validationObject : signatureValidationObjects.getValidationObject()) {
			if (ObjectType.SIGNED_DATA.equals(validationObject.getObjectType())) {
				assertNotNull(validationObject.getId());
				assertEquals(xmlSignerData.getId(), validationObject.getId());
				assertNotNull(validationObject.getPOE());
				expectedSignedDataObjects++;
			}
		}
		assertEquals(1, expectedSignedDataObjects);
		
	}
	
	@Test
	public void xadesManifestSignatureScopeTest() throws Exception {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/plugtest/esig2014/ESIG-XAdES/CZ_SEF/Signature-X-CZ_SEF-4.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		assertNotNull(signatureScopes);
		assertEquals(12, signatureScopes.size());
		
		List<XmlSignerData> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		assertNotNull(originalSignerDocuments);
		assertEquals(12, originalSignerDocuments.size());
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		ValidationObjectListType signatureValidationObjects = etsiValidationReport.getSignatureValidationObjects();
		int signedDataCounter = 0;
		int timestampCounter = 0;
		for (ValidationObjectType validationObject : signatureValidationObjects.getValidationObject()) {
			if (ObjectType.SIGNED_DATA.equals(validationObject.getObjectType())) {
				assertNotNull(validationObject.getId());
				assertNotNull(validationObject.getPOE());
				signedDataCounter++;
			} else if (ObjectType.TIMESTAMP.equals(validationObject.getObjectType())) {
				POEProvisioningType poeProvisioning = validationObject.getPOEProvisioning();
				List<SignatureReferenceType> signatureReferences = poeProvisioning.getSignatureReference();
				assertEquals(1, signatureReferences.size());
				SignatureReferenceType signatureReferenceType = signatureReferences.get(0);
				assertNotNull(signatureReferenceType.getDigestMethod());
				assertNotNull(signatureReferenceType.getDigestValue());
				assertNotNull(signatureReferenceType.getCanonicalizationMethod());
				assertNull(signatureReferenceType.getPAdESFieldName());
				timestampCounter++;
			}
		}
		assertEquals(12, signedDataCounter);
		assertEquals(1, timestampCounter);
	}
	
	@Test
	public void xadesXLevelTest() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xades-x-level.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signatureWrapper);
		
		List<XmlFoundCertificate> allFoundCertificates = signatureWrapper.getAllFoundCertificates();
		assertNotNull(allFoundCertificates);
		assertEquals(4, allFoundCertificates.size());
		
		List<XmlRelatedCertificate> relatedCertificates = signatureWrapper.getRelatedCertificates();
		assertNotNull(relatedCertificates);
		assertEquals(3, relatedCertificates.size());
		for (XmlRelatedCertificate relatedCertificate : relatedCertificates) {
			assertNotNull(relatedCertificate.getCertificate());
			assertTrue(Utils.isCollectionNotEmpty(relatedCertificate.getOrigins()));
		}
		
		List<XmlFoundCertificate> completeCertificateRefs = signatureWrapper.getFoundCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS);
		assertNotNull(completeCertificateRefs);
		assertEquals(3, completeCertificateRefs.size());
		
		List<XmlRevocationRef> completeRevocationRefs = signatureWrapper.getFoundRevocationRefsByOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		assertNotNull(completeRevocationRefs);
		assertEquals(2, completeRevocationRefs.size());
		
		List<String> completeCRLRefs = signatureWrapper.getRevocationIdsByType(RevocationType.CRL);
		assertNotNull(completeCRLRefs);
		assertEquals(1, completeCRLRefs.size());
		
		List<String> completeOCSPRefs = signatureWrapper.getRevocationIdsByType(RevocationType.OCSP);
		assertNotNull(completeOCSPRefs);
		assertEquals(1, completeOCSPRefs.size());
		
	}
	
	@Test
	public void validationDataRefsWithValues() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/plugtest/esig2014/ESIG-XAdES/RO_TRA/Signature-X-RO_TRA-15.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		List<XmlOrphanCertificate> orphanCertificates = signature.getOrphanCertificates();
		assertEquals(3, orphanCertificates.size());
		for (XmlOrphanCertificate orphanCertificate : orphanCertificates) {
			assertNotNull(orphanCertificate.getToken());
			assertTrue(Utils.isCollectionEmpty(orphanCertificate.getOrigins()));
			assertEquals(1, orphanCertificate.getCertificateRefs().size());
			XmlCertificateRef xmlCertificateRef = orphanCertificate.getCertificateRefs().get(0);
			assertEquals(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS, xmlCertificateRef.getOrigin());
			assertNotNull(xmlCertificateRef.getIssuerSerial());
			assertNotNull(xmlCertificateRef.getDigestAlgoAndValue());
			assertNotNull(xmlCertificateRef.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(xmlCertificateRef.getDigestAlgoAndValue().getDigestValue());
		}
		
		List<XmlOrphanRevocation> orphanRevocations = signature.getOrphanRevocations();
		assertEquals(3, orphanRevocations.size());
		int ocspRevocationCounter = 0;
		for (XmlOrphanRevocation orphanRevocation : orphanRevocations) {
			assertNotNull(orphanRevocation.getToken());
			assertNotNull(orphanRevocation.getType());
			if (RevocationType.OCSP.equals(orphanRevocation.getType())) {
				assertNotNull(orphanRevocation.getRevocationRefs().get(0).getProducedAt());
				ocspRevocationCounter++;
			}
		}
		assertEquals(1, ocspRevocationCounter);
		
		List<XmlRevocationRef> allOrphanRevocationRefs = signature.getAllOrphanRevocationRefs();
		assertEquals(3, allOrphanRevocationRefs.size());
		for (XmlRevocationRef revocationRef : allOrphanRevocationRefs) {
			assertNotNull(revocationRef.getOrigin());
			assertNotNull(revocationRef.getDigestAlgoAndValue());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestValue());
		}
		
		List<String> revocationIds = signature.getRevocationIds();
		assertEquals(3, revocationIds.size());
		
		List<XmlOrphanToken> allOrphanCertificates = diagnosticData.getAllOrphanCertificates();
		assertEquals(3, allOrphanCertificates.size());
		for (XmlOrphanToken orphanCertificate : allOrphanCertificates) {
			assertEquals(OrphanTokenType.CERTIFICATE, orphanCertificate.getType());
			assertNotNull(orphanCertificate.getDigestAlgoAndValue());
			assertNotNull(orphanCertificate.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(orphanCertificate.getDigestAlgoAndValue().getDigestValue());
		}
		
		List<XmlOrphanRevocation> allOrphanRevocations = diagnosticData.getAllOrphanRevocations();
		assertEquals(3, allOrphanRevocations.size());
		for (XmlOrphanRevocation orphanRevocation : allOrphanRevocations) {
			assertNotNull(orphanRevocation.getType());
			XmlOrphanToken orphanRevocationToken = orphanRevocation.getToken();
			assertNotNull(orphanRevocationToken);
			assertTrue(revocationIds.contains(orphanRevocationToken.getId()));
			assertEquals(OrphanTokenType.REVOCATION, orphanRevocationToken.getType());
			assertNotNull(orphanRevocationToken.getDigestAlgoAndValue());
			assertNotNull(orphanRevocationToken.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(orphanRevocationToken.getDigestAlgoAndValue().getDigestValue());
		}
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(3, timestampList.size());
		int signatureTimestampCounter = 0;
		int sigAndRefsTimestampCounter = 0;
		int refsOnlyTimestampCounter = 0;
		for (TimestampWrapper timestamp : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestamp.getType())) {
				List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
				assertEquals(3, timestampedObjects.size());
				int signatureTokenCounter = 0;
				int signerDataTokenCounter = 0;
				int certificateTokenCounter = 0;
				for (XmlTimestampedObject timestampedObject : timestampedObjects) {
					XmlAbstractToken token = timestampedObject.getToken();
					assertNotNull(token);
					signatureTokenCounter += token instanceof XmlSignature ? 1 : 0;
					signerDataTokenCounter += token instanceof XmlSignerData ? 1 : 0;
					certificateTokenCounter += token instanceof XmlCertificate ? 1 : 0;
				}
				assertEquals(1, signatureTokenCounter);
				assertEquals(1, signerDataTokenCounter);
				assertEquals(1, certificateTokenCounter);
				signatureTimestampCounter++;
			} else {
				List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
				int orphanCertificateTokenCounter = 0;
				int orphanRevocationTokenCounter = 0;
				for (XmlTimestampedObject timestampedObject : timestampedObjects) {
					XmlAbstractToken token = timestampedObject.getToken();
					assertNotNull(token);
					if (token instanceof XmlOrphanToken) {
						XmlOrphanToken orphanToken = (XmlOrphanToken) token;
						if (OrphanTokenType.CERTIFICATE.equals(orphanToken.getType())) {
							orphanCertificateTokenCounter++;
						} else if (OrphanTokenType.REVOCATION.equals(orphanToken.getType())) {
							orphanRevocationTokenCounter++;
						}
					}
				}
				assertEquals(3, orphanCertificateTokenCounter);
				assertEquals(3, orphanRevocationTokenCounter);
				if (TimestampType.VALIDATION_DATA_TIMESTAMP.equals(timestamp.getType())) {
					assertEquals(11, timestampedObjects.size());
					sigAndRefsTimestampCounter++;
				} else if (TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP.equals(timestamp.getType())) {
					assertEquals(6, timestampedObjects.size());
					refsOnlyTimestampCounter++;
				}
			}
		}
		assertEquals(1, signatureTimestampCounter);
		assertEquals(1, sigAndRefsTimestampCounter);
		assertEquals(1, refsOnlyTimestampCounter);
		
	}
	
	@Test
	public void certificateRefToOCSPResponceCertificateTest() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/plugtest/esig2014/ESIG-XAdES/RO_TRA/Signature-X-RO_TRA-4.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(2, signatures.size());
		boolean signatureFound = false;
		for (SignatureWrapper signature : signatures) {
			if ("Signature-2064753652".equals(signature.getDAIdentifier())) {
				int completeCertificateRefsCounter = 0;
				for (XmlFoundCertificate foundCertificate : signature.getAllFoundCertificates()) {
					List<XmlCertificateRef> certificateRefs = foundCertificate.getCertificateRefs();
					assertEquals(1, certificateRefs.size());
					XmlCertificateRef xmlCertificateRef = certificateRefs.get(0);
					if (CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS.equals(xmlCertificateRef.getOrigin())) {
						completeCertificateRefsCounter++;
					}
					assertTrue(foundCertificate instanceof XmlRelatedCertificate);
					XmlRelatedCertificate relatedCertificate = (XmlRelatedCertificate) foundCertificate;
					assertNotNull(relatedCertificate.getCertificate());
				}
				assertEquals(3, completeCertificateRefsCounter);
				signatureFound = true;
			}
		}
		assertTrue(signatureFound);
		
		List<XmlOrphanToken> allOrphanCertificates = diagnosticData.getAllOrphanCertificates();
		assertEquals(0, allOrphanCertificates.size());
		List<XmlOrphanRevocation> allOrphanRevocations = diagnosticData.getAllOrphanRevocations();
		assertEquals(0, allOrphanRevocations.size());
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(4, timestampList.size());
		for (TimestampWrapper timestamp : timestampList) {
			List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
			for (XmlTimestampedObject timestampedObject : timestampedObjects) {
				assertNotNull(timestampedObject.getToken());
			}
		}
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
