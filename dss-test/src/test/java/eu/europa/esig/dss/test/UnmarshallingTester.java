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
package eu.europa.esig.dss.test;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.module.jakarta.xmlbind.JakartaXmlBindAnnotationIntrospector;
import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAbstractToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificateToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.simplereport.SimpleReportFacade;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.ValidationReportFacade;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class UnmarshallingTester {

	private static final Logger LOG = LoggerFactory.getLogger(UnmarshallingTester.class);

	public static void unmarshallXmlReports(Reports reports) {

		// XML
		XmlDiagnosticData unmarshalled = unmarshallDiagnosticData(reports);
		compareUnmarshalledDiagnosticData(reports, unmarshalled);

		unmarshallDetailedReport(reports);
		unmarshallSimpleReport(reports);
		unmarshallValidationReport(reports);

		// JSON
		mapDiagnosticData(reports);
		mapDetailedReport(reports);
		mapSimpleReport(reports);
		// JSON for ETSI VR is skipped
		// mapValidationReport(reports);
	}

	public static XmlDiagnosticData unmarshallDiagnosticData(Reports reports) {
		XmlDiagnosticData unmarshall = null;
		try {
			String xmlDiagnosticData = reports.getXmlDiagnosticData();
			assertTrue(Utils.isStringNotBlank(xmlDiagnosticData));
//			LOG.info(xmlDiagnosticData);
			unmarshall = DiagnosticDataFacade.newFacade().unmarshall(xmlDiagnosticData);
			assertNotNull(unmarshall);
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the Diagnostic data : {}", e.getMessage(), e);
			fail(e.getMessage());
		}
		return unmarshall;
	}

	public static void mapDiagnosticData(Reports reports) {
		ObjectMapper om = getObjectMapper();

		SimpleModule module = new SimpleModule("XmlTimestampedObjectDeserializerModule");
		XmlTimestampedObjectDeserializer deserializer = new XmlTimestampedObjectDeserializer();
		module.addDeserializer(XmlTimestampedObject.class, deserializer);
		om.registerModule(module);

		try {
			String json = om.writeValueAsString(reports.getDiagnosticDataJaxb());
			assertNotNull(json);
//			LOG.info(json);
			XmlDiagnosticData diagnosticDataObject = om.readValue(json, XmlDiagnosticData.class);
			assertNotNull(diagnosticDataObject);
		} catch (Exception e) {
			LOG.error("Unable to map the Diagnostic data : {}", e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	public static void unmarshallDetailedReport(Reports reports) {
		try {
			String xmlDetailedReport = reports.getXmlDetailedReport();
			assertTrue(Utils.isStringNotBlank(xmlDetailedReport));
//			LOG.info(xmlDetailedReport);
			assertNotNull(DetailedReportFacade.newFacade().unmarshall(xmlDetailedReport));
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the Detailed Report : {}", e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	public static void mapDetailedReport(Reports reports) {
		ObjectMapper om = getObjectMapper();
		try {
			String json = om.writeValueAsString(reports.getDetailedReportJaxb());
			assertNotNull(json);
//			LOG.info(json);
			XmlDetailedReport detailedReportObject = om.readValue(json, XmlDetailedReport.class);
			assertNotNull(detailedReportObject);
		} catch (Exception e) {
			LOG.error("Unable to map the Detailed Report : {}", e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	public static void unmarshallSimpleReport(Reports reports) {
		try {
			String xmlSimpleReport = reports.getXmlSimpleReport();
			assertTrue(Utils.isStringNotBlank(xmlSimpleReport));
//			LOG.info(xmlSimpleReport);
			assertNotNull(SimpleReportFacade.newFacade().unmarshall(xmlSimpleReport));
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the Simple Report : {}", e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	public static void mapSimpleReport(Reports reports) {
		ObjectMapper om = getObjectMapper();
		try {
			String json = om.writeValueAsString(reports.getSimpleReportJaxb());
			assertNotNull(json);
//			LOG.info(json);
			XmlSimpleReport simpleReportObject = om.readValue(json, XmlSimpleReport.class);
			assertNotNull(simpleReportObject);
		} catch (Exception e) {
			LOG.error("Unable to map the Simple Report : {}", e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	public static void unmarshallValidationReport(Reports reports) {
		try {
			String xmlValidationReport = reports.getXmlValidationReport();
			assertTrue(Utils.isStringNotBlank(xmlValidationReport));
//			LOG.info(xmlValidationReport);
			assertNotNull(ValidationReportFacade.newFacade().unmarshall(xmlValidationReport));
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the ETSI Validation Report : {}", e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	private static ObjectMapper getObjectMapper() {
		ObjectMapper om = new ObjectMapper();
		JakartaXmlBindAnnotationIntrospector jai = new JakartaXmlBindAnnotationIntrospector(TypeFactory.defaultInstance());
		om.setAnnotationIntrospector(jai);
		om.enable(SerializationFeature.INDENT_OUTPUT);
		return om;
	}

	private static class XmlTimestampedObjectDeserializer extends StdDeserializer<XmlTimestampedObject> {

		private static final long serialVersionUID = -5743323649165950906L;

		protected XmlTimestampedObjectDeserializer() {
			super(XmlTimestampedObject.class);
		}

		@Override
		public XmlTimestampedObject deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
			ObjectMapper mapper = (ObjectMapper) jp.getCodec();
			ObjectNode root = mapper.readTree(jp);
			JsonNode categoryNode = root.get("Category");
			TimestampedObjectType category = TimestampedObjectType.valueOf(categoryNode.textValue());
			JsonNode tokenNode = root.get("Token");

			XmlTimestampedObject timestampedObject = new XmlTimestampedObject();
			timestampedObject.setCategory(category);

			XmlAbstractToken token;
			switch (category) {
				case SIGNATURE:
					token = new XmlSignature();
					break;
				case CERTIFICATE:
					token = new XmlCertificate();
					break;
				case REVOCATION:
					token = new XmlRevocation();
					break;
				case TIMESTAMP:
					token = new XmlTimestamp();
					break;
				case EVIDENCE_RECORD:
					token = new XmlEvidenceRecord();
					break;
				case SIGNED_DATA:
					token = new XmlSignerData();
					break;
				case ORPHAN_CERTIFICATE:
					token = new XmlOrphanCertificateToken();
					break;
				case ORPHAN_REVOCATION:
					token = new XmlOrphanRevocationToken();
					break;
				default:
					throw new InvalidFormatException(jp, "Unsupported category value " + category, category, TimestampedObjectType.class);
			}

			token.setId(tokenNode.textValue());
			timestampedObject.setToken(token);
			return timestampedObject;
		}

	}

	private static void compareUnmarshalledDiagnosticData(Reports reports, XmlDiagnosticData unmarshalledJaxb) {
		final DiagnosticData original = reports.getDiagnosticData();
		final DiagnosticData unmarshalled = new DiagnosticData(unmarshalledJaxb);

		assertEquals(original.getAllSignatures().size(), unmarshalled.getAllSignatures().size());
		assertEquals(original.getAllCounterSignatures().size(), unmarshalled.getAllCounterSignatures().size());
		assertEquals(original.getAllOrphanCertificateObjects().size(), unmarshalled.getAllOrphanCertificateObjects().size());
		assertEquals(original.getAllRevocationData().size(), unmarshalled.getAllRevocationData().size());
		assertEquals(original.getAllOrphanRevocationObjects().size(), unmarshalled.getAllOrphanRevocationObjects().size());
		assertEquals(original.getListOfTrustedLists().size(), unmarshalled.getListOfTrustedLists().size());
		assertEquals(original.getUsedCertificates().size(), unmarshalled.getUsedCertificates().size());
		assertEquals(original.getTimestampList().size(), unmarshalled.getTimestampList().size());
		assertEquals(original.getAllSignerDocuments().size(), unmarshalled.getAllSignerDocuments().size());

		compareUnmarshalledCertificates(original, unmarshalled.getUsedCertificates());
		compareUnmarshalledTimestamps(original, unmarshalled.getTimestampList());
		compareUnmarshalledRevocations(original, unmarshalled.getAllRevocationData());
		compareUnmarshalledSignatures(original, unmarshalled.getAllSignatures());
		compareUnmarshalledSignatures(original, unmarshalled.getAllCounterSignatures());
	}

	private static void compareUnmarshalledSignatures(final DiagnosticData original, final Set<SignatureWrapper> unmarshalledSigs) {
		for (SignatureWrapper unmarshalledSig : unmarshalledSigs) {
			SignatureWrapper originalSignature = original.getSignatureById(unmarshalledSig.getId());

			if (unmarshalledSig.getSigningCertificate() == null) {
				assertNull(originalSignature.getSigningCertificate());
			} else {
				assertEquals(unmarshalledSig.getSigningCertificate().getId(), originalSignature.getSigningCertificate().getId());
			}
			assertEquals(unmarshalledSig.foundCertificates().getOrphanCertificates().size(), originalSignature.foundCertificates().getOrphanCertificates().size());
			assertEquals(unmarshalledSig.foundCertificates().getRelatedCertificates().size(), originalSignature.foundCertificates().getRelatedCertificates().size());
			assertEquals(unmarshalledSig.foundCertificates().getRelatedCertificateRefs().size(), originalSignature.foundCertificates().getRelatedCertificateRefs().size());
			assertEquals(unmarshalledSig.foundCertificates().getOrphanCertificateRefs().size(), originalSignature.foundCertificates().getOrphanCertificateRefs().size());
			assertEquals(unmarshalledSig.foundRevocations().getRelatedRevocationData().size(), originalSignature.foundRevocations().getRelatedRevocationData().size());
			assertEquals(unmarshalledSig.foundRevocations().getOrphanRevocationData().size(), originalSignature.foundRevocations().getOrphanRevocationData().size());
			assertEquals(unmarshalledSig.foundRevocations().getRelatedRevocationRefs().size(), originalSignature.foundRevocations().getRelatedRevocationRefs().size());
			assertEquals(unmarshalledSig.foundRevocations().getOrphanRevocationRefs().size(), originalSignature.foundRevocations().getOrphanRevocationRefs().size());
			assertEquals(unmarshalledSig.getCertificateChain().size(), originalSignature.getCertificateChain().size());
			assertEquals(unmarshalledSig.getCertifiedRoles().size(), originalSignature.getCertifiedRoles().size());
			assertEquals(unmarshalledSig.getClaimedRoles().size(), originalSignature.getClaimedRoles().size());
			assertEquals(unmarshalledSig.getCommitmentTypeIndications().size(), originalSignature.getCommitmentTypeIndications().size());
			assertEquals(unmarshalledSig.getDigestMatchers().size(), originalSignature.getDigestMatchers().size());
			assertEquals(unmarshalledSig.getTimestampList().size(), originalSignature.getTimestampList().size());
			assertEquals(unmarshalledSig.getSignerRoles().size(), originalSignature.getSignerRoles().size());
			assertEquals(unmarshalledSig.getSignatureScopes().size(), originalSignature.getSignatureScopes().size());
			assertEquals(unmarshalledSig.getSignatureInformationStore().size(), originalSignature.getSignatureInformationStore().size());
			assertEquals(unmarshalledSig.getDigestAlgorithm(), originalSignature.getDigestAlgorithm());
			assertEquals(unmarshalledSig.getEncryptionAlgorithm(), originalSignature.getEncryptionAlgorithm());

			compareUnmarshalledCertificates(original, unmarshalledSig.getCertificateChain());
			compareUnmarshalledTimestamps(original, unmarshalledSig.getTimestampList());
		}
	}

	private static void compareUnmarshalledRevocations(DiagnosticData original, Set<RevocationWrapper> unmarshalledRevocations) {
		for (RevocationWrapper unmarshalledRevocation : unmarshalledRevocations) {
			RevocationWrapper originalRevocationData = null;
			for (RevocationWrapper revocationWrapper : original.getAllRevocationData()) {
				if (revocationWrapper.getId().equals(unmarshalledRevocation.getId())) {
					originalRevocationData = revocationWrapper;
					break;
				}
			}
			assertNotNull(originalRevocationData);

			if (unmarshalledRevocation.getSigningCertificate() == null) {
				assertNull(originalRevocationData.getSigningCertificate());
			} else {
				assertEquals(unmarshalledRevocation.getSigningCertificate().getId(), originalRevocationData.getSigningCertificate().getId());
			}
			assertEquals(unmarshalledRevocation.getCertificateChain().size(), originalRevocationData.getCertificateChain().size());
			assertEquals(unmarshalledRevocation.getDigestMatchers().size(), originalRevocationData.getDigestMatchers().size());

			compareUnmarshalledCertificates(original, unmarshalledRevocation.getCertificateChain());
		}
	}

	private static void compareUnmarshalledTimestamps(final DiagnosticData original, List<TimestampWrapper> unmarshalledTimestamps) {
		for (TimestampWrapper unmarshalledTst : unmarshalledTimestamps) {
			TimestampWrapper originalTst = original.getTimestampById(unmarshalledTst.getId());
			assertNotNull(originalTst);

			if (unmarshalledTst.getSigningCertificate() == null) {
				assertNull(originalTst.getSigningCertificate());
			} else {
				assertEquals(unmarshalledTst.getSigningCertificate().getId(), originalTst.getSigningCertificate().getId());
			}
			assertEquals(unmarshalledTst.getCertificateChain().size(), originalTst.getCertificateChain().size());
			assertEquals(unmarshalledTst.getAllTimestampedOrphanTokens().size(), originalTst.getAllTimestampedOrphanTokens().size());
			assertEquals(unmarshalledTst.getDigestMatchers().size(), originalTst.getDigestMatchers().size());
			assertEquals(unmarshalledTst.getCertificateChain().size(), originalTst.getCertificateChain().size());
			assertEquals(unmarshalledTst.getTimestampedObjects().size(), originalTst.getTimestampedObjects().size());
			assertEquals(unmarshalledTst.getSignatureInformationStore().size(), originalTst.getSignatureInformationStore().size());

			compareUnmarshalledCertificates(original, unmarshalledTst.getCertificateChain());
		}
	}

	private static void compareUnmarshalledCertificates(final DiagnosticData original, List<CertificateWrapper> unmarshalledCertificates) {
		for (CertificateWrapper unmarshalledCert : unmarshalledCertificates) {
			CertificateWrapper originalCert = original.getUsedCertificateById(unmarshalledCert.getId());
			assertNotNull(originalCert);
			assertEquals(unmarshalledCert.getCertificateChain().size(), originalCert.getCertificateChain().size());
			assertEquals(unmarshalledCert.getCAIssuersAccessUrls().size(), originalCert.getCAIssuersAccessUrls().size());
			assertEquals(unmarshalledCert.getOCSPAccessUrls().size(), originalCert.getOCSPAccessUrls().size());
			assertEquals(unmarshalledCert.getCRLDistributionPoints().size(), originalCert.getCRLDistributionPoints().size());
			assertEquals(unmarshalledCert.getPolicyIds().size(), originalCert.getPolicyIds().size());
			assertEquals(unmarshalledCert.getCertificateRevocationData().size(), originalCert.getCertificateRevocationData().size());
			assertEquals(unmarshalledCert.getExtendedKeyUsages().size(), originalCert.getExtendedKeyUsages().size());
			assertEquals(unmarshalledCert.getTrustServices().size(), originalCert.getTrustServices().size());
			assertEquals(unmarshalledCert.getTrustServiceProviders().size(), originalCert.getTrustServiceProviders().size());

			if (unmarshalledCert.getSigningCertificate() != null && !unmarshalledCert.getId().equals(unmarshalledCert.getSigningCertificate().getId())) {
				compareUnmarshalledCertificates(original, unmarshalledCert.getCertificateChain());
			}
		}
	}

}
