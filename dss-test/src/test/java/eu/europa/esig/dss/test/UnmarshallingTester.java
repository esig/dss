/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
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
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAbstractToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlArchiveTimestampHashIndex;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAuthorityInformationAccess;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAuthorityKeyIdentifier;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicConstraints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlByteRange;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCRLDistributionPoints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateContentEquivalence;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateExtension;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicies;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCommitmentTypeIndication;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDistinguishedName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDocMDP;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.diagnostic.jaxb.XmlExtendedKeyUsages;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificates;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundEvidenceRecord;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundRevocations;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlGeneralName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlGeneralSubtree;
import eu.europa.esig.dss.diagnostic.jaxb.XmlIdPkixOcspNoCheck;
import eu.europa.esig.dss.diagnostic.jaxb.XmlInhibitAnyPolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlIssuerSerial;
import eu.europa.esig.dss.diagnostic.jaxb.XmlKeyUsages;
import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlMRACertificateMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlMRATrustServiceMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModificationDetection;
import eu.europa.esig.dss.diagnostic.jaxb.XmlNameConstraints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlNoRevAvail;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModifications;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOriginalThirdCountryQcStatementsMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOriginalThirdCountryTrustServiceMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificateToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanTokens;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFAInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFLockDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureField;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPSD2QcInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicyConstraints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicyDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcCompliance;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcEuLimitValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcSSCD;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQualifier;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRoleOfPSP;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSPDocSpecification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureDigestReference;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignaturePolicyStore;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureProductionPlace;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerDocumentRepresentations;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerRole;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStructuralValidation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSubjectAlternativeNames;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSubjectKeyIdentifier;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTSAGeneralName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustService;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustServiceEquivalenceInformation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustServiceProvider;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrusted;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.diagnostic.jaxb.XmlUserNotice;
import eu.europa.esig.dss.diagnostic.jaxb.XmlValAssuredShortTermCertificate;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.simplereport.SimpleReportFacade;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.ValidationReportFacade;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class UnmarshallingTester {

	private static final Logger LOG = LoggerFactory.getLogger(UnmarshallingTester.class);

	public static void unmarshallXmlReports(Reports reports) {

		// XML
		XmlDiagnosticData unmarshalled = unmarshallDiagnosticData(reports);
		compareUnmarshalledDiagnosticData(reports.getDiagnosticDataJaxb(), unmarshalled);

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
			compareUnmarshalledDiagnosticData(reports.getDiagnosticDataJaxb(), diagnosticDataObject);
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

	private static void compareUnmarshalledDiagnosticData(XmlDiagnosticData originalJaxb, XmlDiagnosticData unmarshalledJaxb) {
		assertEquals(originalJaxb.getDocumentName(), unmarshalledJaxb.getDocumentName());
		assertDateEquals(originalJaxb.getValidationDate(), unmarshalledJaxb.getValidationDate());
		assertXmlContainerInfoEquals(originalJaxb.getContainerInfo(), unmarshalledJaxb.getContainerInfo());
		compareXmlPDFAInfo(originalJaxb.getPDFAInfo(), unmarshalledJaxb.getPDFAInfo());
		compareXmlSignatures(originalJaxb.getSignatures(), unmarshalledJaxb.getSignatures());
		compareXmlEvidenceRecords(originalJaxb.getEvidenceRecords(), unmarshalledJaxb.getEvidenceRecords());
		compareXmlCertificates(originalJaxb.getUsedCertificates(), unmarshalledJaxb.getUsedCertificates());
		compareXmlRevocations(originalJaxb.getUsedRevocations(), unmarshalledJaxb.getUsedRevocations());
		compareXmlTimestamps(originalJaxb.getUsedTimestamps(), unmarshalledJaxb.getUsedTimestamps());
		compareXmlOrphanTokens(originalJaxb.getOrphanTokens(), unmarshalledJaxb.getOrphanTokens());
		compareXmlSignerDatas(originalJaxb.getOriginalDocuments(), unmarshalledJaxb.getOriginalDocuments());
		compareXmlTrustedLists(originalJaxb.getTrustedLists(), unmarshalledJaxb.getTrustedLists());
	}

	private static void assertXmlContainerInfoEquals(XmlContainerInfo containerInfo1, XmlContainerInfo containerInfo2) {
		assertEquals(containerInfo1 == null, containerInfo2 == null);
		if (containerInfo1 != null) {
			assertEquals(containerInfo1.getContainerType(), containerInfo2.getContainerType());
			assertEquals(containerInfo1.getZipComment(), containerInfo2.getZipComment());
			assertEquals(containerInfo1.isMimeTypeFilePresent(), containerInfo2.isMimeTypeFilePresent());
			assertEquals(containerInfo1.getMimeTypeContent(), containerInfo2.getMimeTypeContent());
			compareXmlManifestFiles(containerInfo1.getManifestFiles(), containerInfo2.getManifestFiles());
			assertEquals(containerInfo1.getContentFiles(), containerInfo2.getContentFiles());
		}
	}

	private static void compareXmlManifestFiles(List<XmlManifestFile> manifestFiles1, List<XmlManifestFile> manifestFiles2) {
		assertEquals(Utils.collectionSize(manifestFiles1), Utils.collectionSize(manifestFiles2));
		if (Utils.isCollectionNotEmpty(manifestFiles1)) {
			for (int i = 0; i < manifestFiles1.size(); i++) {
				compareXmlManifestFile(manifestFiles1.get(i), manifestFiles2.get(i));
			}
		}
	}

	private static void compareXmlManifestFile(XmlManifestFile manifestFile1, XmlManifestFile manifestFile2) {
		assertEquals(manifestFile1.getFilename(), manifestFile2.getFilename());
		assertEquals(manifestFile1.getSignatureFilename(), manifestFile2.getSignatureFilename());
		assertEquals(manifestFile1.getEntries(), manifestFile2.getEntries());
	}

	private static void compareXmlPDFAInfo(XmlPDFAInfo pdfaInfo1, XmlPDFAInfo pdfaInfo2) {
		assertEquals(pdfaInfo1 == null, pdfaInfo2 == null);
		if (pdfaInfo1 != null) {
			assertEquals(pdfaInfo1.getProfileId(), pdfaInfo2.getProfileId());
			assertEquals(pdfaInfo1.getValidationMessages(), pdfaInfo2.getValidationMessages());
			assertEquals(pdfaInfo1.isCompliant(), pdfaInfo2.isCompliant());
		}
	}

	private static void compareXmlSignatures(List<XmlSignature> signatures1, List<XmlSignature> signatures2) {
		assertEquals(Utils.collectionSize(signatures1), Utils.collectionSize(signatures2));
		if (Utils.isCollectionNotEmpty(signatures1)) {
			for (int i = 0; i < signatures1.size(); i++) {
				compareXmlSignature(signatures1.get(i), signatures2.get(i));
			}
		}
	}

	private static void compareXmlAbstractToken(XmlAbstractToken abstractToken1, XmlAbstractToken abstractToken2) {
		assertEquals(abstractToken1.getId(), abstractToken2.getId());
		assertEquals(abstractToken1.isDuplicated(), abstractToken2.isDuplicated());
	}

	private static void compareXmlSignature(XmlSignature xmlSignature1, XmlSignature xmlSignature2) {
		compareXmlAbstractToken(xmlSignature1, xmlSignature2);
		assertEquals(xmlSignature1.getDAIdentifier(), xmlSignature2.getDAIdentifier());
		assertEquals(xmlSignature1.getSignatureFilename(), xmlSignature2.getSignatureFilename());
		assertEquals(xmlSignature1.getErrorMessage(), xmlSignature2.getErrorMessage());
		assertDateEquals(xmlSignature1.getClaimedSigningTime(), xmlSignature2.getClaimedSigningTime());
		assertEquals(xmlSignature1.getSignatureFormat(), xmlSignature2.getSignatureFormat());
		assertEquals(xmlSignature1.getSignatureType(), xmlSignature2.getSignatureType());
		compareXmlStructuralValidation(xmlSignature1.getStructuralValidation(), xmlSignature2.getStructuralValidation());
		compareXmlDigestMatchers(xmlSignature1.getDigestMatchers(), xmlSignature2.getDigestMatchers());
		compareXmlBasicSignature(xmlSignature1.getBasicSignature(), xmlSignature2.getBasicSignature());
		compareSigningCertificate(xmlSignature1.getSigningCertificate(), xmlSignature2.getSigningCertificate());
		compareCertificateChain(xmlSignature1.getCertificateChain(), xmlSignature2.getCertificateChain());
		assertEquals(xmlSignature1.getContentType(), xmlSignature2.getContentType());
		assertEquals(xmlSignature1.getMimeType(), xmlSignature2.getMimeType());
		assertEquals(xmlSignature1.getContentIdentifier(), xmlSignature2.getContentIdentifier());
		assertEquals(xmlSignature1.getContentHints(), xmlSignature2.getContentHints());
		assertEquals(xmlSignature1.getSignatureType(), xmlSignature2.getSignatureType());
		compareSignatureProductionPlace(xmlSignature1.getSignatureProductionPlace(), xmlSignature2.getSignatureProductionPlace());
		compareCommitmentTypeIndications(xmlSignature1.getCommitmentTypeIndications(), xmlSignature2.getCommitmentTypeIndications());
		compareSignerRoles(xmlSignature1.getSignerRole(), xmlSignature2.getSignerRole());
		compareXmlPolicy(xmlSignature1.getPolicy(), xmlSignature2.getPolicy());
		compareXmlSignaturePolicyStore(xmlSignature1.getSignaturePolicyStore(), xmlSignature2.getSignaturePolicyStore());
		compareXmlSignerInfos(xmlSignature1.getSignerInformationStore(), xmlSignature2.getSignerInformationStore());
		compareXmlPdfRevision(xmlSignature1.getPDFRevision(), xmlSignature2.getPDFRevision());
		assertDateEquals(xmlSignature1.getVRIDictionaryCreationTime(), xmlSignature2.getVRIDictionaryCreationTime());
		compareXmlSignerDocumentRepresentations(xmlSignature1.getSignerDocumentRepresentations(), xmlSignature2.getSignerDocumentRepresentations());
		compareXmlFoundCertificates(xmlSignature1.getFoundCertificates(), xmlSignature2.getFoundCertificates());
		compareXmlFoundRevocations(xmlSignature1.getFoundRevocations(), xmlSignature2.getFoundRevocations());
		compareXmlFoundTimestamps(xmlSignature1.getFoundTimestamps(), xmlSignature2.getFoundTimestamps());
		compareXmlFoundEvidenceRecords(xmlSignature1.getFoundEvidenceRecords(), xmlSignature2.getFoundEvidenceRecords());
		compareXmlSignatureScopes(xmlSignature1.getSignatureScopes(), xmlSignature2.getSignatureScopes());
		compareXmlSignatureDigestReference(xmlSignature1.getSignatureDigestReference(), xmlSignature2.getSignatureDigestReference());
		compareXmDigestAlgoAndValue(xmlSignature1.getDataToBeSignedRepresentation(), xmlSignature2.getDataToBeSignedRepresentation());
		assertArrayEquals(xmlSignature1.getSignatureValue(), xmlSignature2.getSignatureValue());
		assertEquals(xmlSignature1.isCounterSignature(), xmlSignature2.isCounterSignature());
		compareXmlTokenIDREF(xmlSignature1.getParent(), xmlSignature2.getParent());

		assertEquals(xmlSignature1.getDAIdentifier(), xmlSignature2.getDAIdentifier());
	}

	private static void compareXmlStructuralValidation(XmlStructuralValidation structuralValidation1, XmlStructuralValidation structuralValidation2) {
		assertEquals(structuralValidation1 == null, structuralValidation2 == null);
		if (structuralValidation1 != null) {
			assertEquals(structuralValidation1.getMessages(), structuralValidation2.getMessages());
			assertEquals(structuralValidation1.isValid(), structuralValidation2.isValid());
		}
	}

	private static void compareXmlDigestMatchers(List<XmlDigestMatcher> digestMatchers1, List<XmlDigestMatcher> digestMatchers2) {
		assertEquals(Utils.collectionSize(digestMatchers1), Utils.collectionSize(digestMatchers2));
		if (Utils.isCollectionNotEmpty(digestMatchers1)) {
			for (int i = 0; i < digestMatchers1.size(); i++) {
				compareXmlDigestMatcher(digestMatchers1.get(i), digestMatchers2.get(i));
			}
		}
	}

	private static void compareXmlDigestMatcher(XmlDigestMatcher xmlDigestMatcher1, XmlDigestMatcher xmlDigestMatcher2) {
		compareXmDigestAlgoAndValue(xmlDigestMatcher1, xmlDigestMatcher2);
		assertEquals(xmlDigestMatcher1.isDataFound(), xmlDigestMatcher2.isDataFound());
		assertEquals(xmlDigestMatcher1.isDataIntact(), xmlDigestMatcher2.isDataIntact());
		assertEquals(xmlDigestMatcher1.getType(), xmlDigestMatcher2.getType());
		assertEquals(xmlDigestMatcher1.getId(), xmlDigestMatcher2.getId());
		assertEquals(xmlDigestMatcher1.getUri(), xmlDigestMatcher2.getUri());
		assertEquals(xmlDigestMatcher1.getDocumentName(), xmlDigestMatcher2.getDocumentName());
		assertEquals(xmlDigestMatcher1.isDuplicated(), xmlDigestMatcher2.isDuplicated());
	}

	private static void compareXmDigestAlgoAndValue(XmlDigestAlgoAndValue digestAlgoAndValue1, XmlDigestAlgoAndValue digestAlgoAndValue2) {
		assertEquals(digestAlgoAndValue1 == null, digestAlgoAndValue2 == null);
		if (digestAlgoAndValue1 != null) {
			assertEquals(digestAlgoAndValue1.getDigestMethod(), digestAlgoAndValue2.getDigestMethod());
			assertArrayEquals(digestAlgoAndValue1.getDigestValue(), digestAlgoAndValue2.getDigestValue());
			assertEquals(digestAlgoAndValue1.isMatch(), digestAlgoAndValue2.isMatch());
		}
	}

	private static void compareXmlBasicSignature(XmlBasicSignature basicSignature1, XmlBasicSignature basicSignature2) {
		assertEquals(basicSignature1 == null, basicSignature2 == null);
		if (basicSignature1 != null) {
			assertEquals(basicSignature1.getEncryptionAlgoUsedToSignThisToken(), basicSignature2.getEncryptionAlgoUsedToSignThisToken());
			assertEquals(basicSignature1.getKeyLengthUsedToSignThisToken(), basicSignature2.getKeyLengthUsedToSignThisToken());
			assertEquals(basicSignature1.getDigestAlgoUsedToSignThisToken(), basicSignature2.getDigestAlgoUsedToSignThisToken());
			assertEquals(basicSignature1.isSignatureIntact(), basicSignature2.isSignatureIntact());
			assertEquals(basicSignature1.isSignatureValid(), basicSignature2.isSignatureValid());
		}
	}
	
	private static void compareSigningCertificate(XmlSigningCertificate signingCertificate1, XmlSigningCertificate signingCertificate2) {
		assertEquals(signingCertificate1 == null, signingCertificate2 == null);
		if (signingCertificate1 != null) {
			assertArrayEquals(signingCertificate1.getPublicKey(), signingCertificate2.getPublicKey());
			compareXmlTokenIDREF(signingCertificate1.getCertificate(), signingCertificate2.getCertificate());
		}
	}

	private static void compareXmlTokenIDREF(XmlAbstractToken xmlToken1, XmlAbstractToken xmlToken2) {
		assertEquals(xmlToken1 == null, xmlToken2 == null);
		if (xmlToken1 != null) {
			assertEquals(xmlToken1.getId(), xmlToken2.getId());
		}
	}
	
	private static void compareCertificateChain(List<XmlChainItem> chainItems1, List<XmlChainItem> chainItems2) {
		assertEquals(Utils.collectionSize(chainItems1), Utils.collectionSize(chainItems2));
		if (Utils.isCollectionNotEmpty(chainItems1)) {
			for (int i = 0; i < chainItems1.size(); i++) {
				compareXmlTokenIDREF(chainItems1.get(i).getCertificate(), chainItems2.get(i).getCertificate());
			}
		}
	}

	private static void compareSignatureProductionPlace(XmlSignatureProductionPlace signatureProductionPlace1, XmlSignatureProductionPlace signatureProductionPlace2) {
		assertEquals(signatureProductionPlace1 == null, signatureProductionPlace2 == null);
		if (signatureProductionPlace1 != null) {
			assertEquals(signatureProductionPlace1.getPostalAddress(), signatureProductionPlace2.getPostalAddress());
			assertEquals(signatureProductionPlace1.getCity(), signatureProductionPlace2.getCity());
			assertEquals(signatureProductionPlace1.getStateOrProvince(), signatureProductionPlace2.getStateOrProvince());
			assertEquals(signatureProductionPlace1.getPostOfficeBoxNumber(), signatureProductionPlace2.getPostOfficeBoxNumber());
			assertEquals(signatureProductionPlace1.getPostalCode(), signatureProductionPlace2.getPostalCode());
			assertEquals(signatureProductionPlace1.getCountryName(), signatureProductionPlace2.getCountryName());
			assertEquals(signatureProductionPlace1.getStreetAddress(), signatureProductionPlace2.getStreetAddress());
		}
	}

	private static void compareCommitmentTypeIndications(List<XmlCommitmentTypeIndication> commitmentTypeIndications1, List<XmlCommitmentTypeIndication> commitmentTypeIndications2) {
		assertEquals(Utils.collectionSize(commitmentTypeIndications1), Utils.collectionSize(commitmentTypeIndications2));
		if (Utils.isCollectionNotEmpty(commitmentTypeIndications1)) {
			for (int i = 0; i < commitmentTypeIndications1.size(); i++) {
				compareXmlCommitmentTypeIndication(commitmentTypeIndications1.get(i), commitmentTypeIndications2.get(i));
			}
		}
	}

	private static void compareXmlCommitmentTypeIndication(XmlCommitmentTypeIndication xmlCommitmentTypeIndication1, XmlCommitmentTypeIndication xmlCommitmentTypeIndication2) {
		assertEquals(xmlCommitmentTypeIndication1.getIdentifier(), xmlCommitmentTypeIndication2.getIdentifier());
		assertEquals(xmlCommitmentTypeIndication1.getDescription(), xmlCommitmentTypeIndication2.getDescription());
		assertEquals(xmlCommitmentTypeIndication1.getDocumentationReferences(), xmlCommitmentTypeIndication2.getDocumentationReferences());
		assertEquals(xmlCommitmentTypeIndication1.getObjectReferences(), xmlCommitmentTypeIndication2.getObjectReferences());
		assertEquals(xmlCommitmentTypeIndication1.isAllDataSignedObjects(), xmlCommitmentTypeIndication2.isAllDataSignedObjects());
	}

	private static void compareSignerRoles(List<XmlSignerRole> signerRole1, List<XmlSignerRole> signerRole2) {
		assertEquals(Utils.collectionSize(signerRole1), Utils.collectionSize(signerRole2));
		if (Utils.isCollectionNotEmpty(signerRole1)) {
			for (int i = 0; i < signerRole1.size(); i++) {
				compareXmlSignerRole(signerRole1.get(i), signerRole2.get(i));
			}
		}
	}

	private static void compareXmlSignerRole(XmlSignerRole xmlSignerRole1, XmlSignerRole xmlSignerRole2) {
		assertEquals(xmlSignerRole1.getRole(), xmlSignerRole2.getRole());
		assertDateEquals(xmlSignerRole1.getNotAfter(), xmlSignerRole2.getNotAfter());
		assertDateEquals(xmlSignerRole1.getNotBefore(), xmlSignerRole2.getNotBefore());
		assertEquals(xmlSignerRole1.getCategory(), xmlSignerRole2.getCategory());
	}

	private static void compareXmlPolicy(XmlPolicy policy1, XmlPolicy policy2) {
		assertEquals(policy1 == null, policy2 == null);
		if (policy1 != null) {
			assertEquals(policy1.getId(), policy2.getId());
			assertEquals(policy1.getUrl(), policy2.getUrl());
			compareXmlUserNotice(policy1.getUserNotice(), policy2.getUserNotice());
			compareXmlSPDocSpecification(policy1.getDocSpecification(), policy2.getDocSpecification());
			assertEquals(policy1.getDescription(), policy2.getDescription());
			assertEquals(policy1.isIdentified(), policy2.isIdentified());
			assertEquals(policy1.isAsn1Processable(), policy2.isAsn1Processable());
			assertEquals(policy1.getTransformations(), policy2.getTransformations());
			assertEquals(policy1.getDocumentationReferences(), policy2.getDocumentationReferences());
			assertEquals(policy1.getProcessingError(), policy2.getProcessingError());
			compareXmlPolicyDigestAlgoAndValue(policy1.getDigestAlgoAndValue(), policy2.getDigestAlgoAndValue());
		}
	}

	private static void compareXmlUserNotice(XmlUserNotice userNotice1, XmlUserNotice userNotice2) {
		assertEquals(userNotice1 == null, userNotice2 == null);
		if (userNotice1 != null) {
			assertEquals(userNotice1.getOrganization(), userNotice2.getOrganization());
			assertEquals(userNotice1.getNoticeNumbers(), userNotice2.getNoticeNumbers());
			assertEquals(userNotice1.getExplicitText(), userNotice2.getExplicitText());
		}
	}

	private static void compareXmlSPDocSpecification(XmlSPDocSpecification docSpecification1, XmlSPDocSpecification docSpecification2) {
		assertEquals(docSpecification1 == null, docSpecification2 == null);
		if (docSpecification1 != null) {
			assertEquals(docSpecification1.getId(), docSpecification2.getId());
			assertEquals(docSpecification1.getDescription(), docSpecification2.getDescription());
			assertEquals(docSpecification1.getDocumentationReferences(), docSpecification2.getDocumentationReferences());
		}
	}

	private static void compareXmlPolicyDigestAlgoAndValue(XmlPolicyDigestAlgoAndValue digestAlgoAndValue1, XmlPolicyDigestAlgoAndValue digestAlgoAndValue2) {
		assertEquals(digestAlgoAndValue1 == null, digestAlgoAndValue2 == null);
		if (digestAlgoAndValue1 != null) {
			compareXmDigestAlgoAndValue(digestAlgoAndValue1, digestAlgoAndValue2);
			assertEquals(digestAlgoAndValue1.isDigestAlgorithmsEqual(), digestAlgoAndValue2.isDigestAlgorithmsEqual());
			assertEquals(digestAlgoAndValue1.isZeroHash(), digestAlgoAndValue2.isZeroHash());
		}
	}

	private static void compareXmlSignaturePolicyStore(XmlSignaturePolicyStore signaturePolicyStore1, XmlSignaturePolicyStore signaturePolicyStore2) {
		assertEquals(signaturePolicyStore1 == null, signaturePolicyStore2 == null);
		if (signaturePolicyStore1 != null) {
			compareXmlSPDocSpecification(signaturePolicyStore1, signaturePolicyStore2);
			assertEquals(signaturePolicyStore1.getSigPolDocLocalURI(), signaturePolicyStore2.getSigPolDocLocalURI());
			compareXmDigestAlgoAndValue(signaturePolicyStore1.getDigestAlgoAndValue(), signaturePolicyStore2.getDigestAlgoAndValue());
		}
	}

	private static void compareXmlSignerInfos(List<XmlSignerInfo> signerInfos1, List<XmlSignerInfo> signerInfos2) {
		assertEquals(Utils.collectionSize(signerInfos1), Utils.collectionSize(signerInfos2));
		if (Utils.isCollectionNotEmpty(signerInfos1)) {
			for (int i = 0; i < signerInfos1.size(); i++) {
				compareXmlSignerInfo(signerInfos1.get(i), signerInfos2.get(i));
			}
		}
	}

	private static void compareXmlSignerInfo(XmlSignerInfo xmlSignerInfo1, XmlSignerInfo xmlSignerInfo2) {
		assertEquals(xmlSignerInfo1 == null, xmlSignerInfo2 == null);
		if (xmlSignerInfo1 != null) {
			assertEquals(xmlSignerInfo1.getIssuerName(), xmlSignerInfo2.getIssuerName());
			assertEquals(xmlSignerInfo1.getSerialNumber(), xmlSignerInfo2.getSerialNumber());
			assertArrayEquals(xmlSignerInfo1.getSki(), xmlSignerInfo2.getSki());
			assertEquals(xmlSignerInfo1.isCurrent(), xmlSignerInfo2.isCurrent());
		}
	}

	private static void compareXmlPdfRevision(XmlPDFRevision pdfRevision1, XmlPDFRevision pdfRevision2) {
		assertEquals(pdfRevision1 == null, pdfRevision2 == null);
		if (pdfRevision1 != null) {
			compareXmlPDFSignatureFields(pdfRevision1.getFields(), pdfRevision2.getFields());
			compareXmlPDFSignatureDictionary(pdfRevision1.getPDFSignatureDictionary(), pdfRevision2.getPDFSignatureDictionary());
			compareXmlModificationDetection(pdfRevision1.getModificationDetection(), pdfRevision2.getModificationDetection());
		}
	}

	private static void compareXmlPDFSignatureFields(List<XmlPDFSignatureField> fields1, List<XmlPDFSignatureField> fields2) {
		assertEquals(Utils.collectionSize(fields1), Utils.collectionSize(fields2));
		if (Utils.isCollectionNotEmpty(fields1)) {
			for (int i = 0; i < fields1.size(); i++) {
				compareXmlPDFSignatureField(fields1.get(i), fields2.get(i));
			}
		}
	}

	private static void compareXmlPDFSignatureField(XmlPDFSignatureField xmlPDFSignatureField1, XmlPDFSignatureField xmlPDFSignatureField2) {
		compareXmlPDFLockDictionary(xmlPDFSignatureField1.getSigFieldLock(), xmlPDFSignatureField2.getSigFieldLock());
		assertEquals(xmlPDFSignatureField1.getName(), xmlPDFSignatureField2.getName());
	}

	private static void compareXmlPDFLockDictionary(XmlPDFLockDictionary sigFieldLock1, XmlPDFLockDictionary sigFieldLock2) {
		assertEquals(sigFieldLock1 == null, sigFieldLock2 == null);
		if (sigFieldLock1 != null) {
			assertEquals(sigFieldLock1.getAction(), sigFieldLock2.getAction());
			assertEquals(sigFieldLock1.getFields(), sigFieldLock2.getFields());
			assertEquals(sigFieldLock1.getPermissions(), sigFieldLock2.getPermissions());
		}
	}

	private static void compareXmlPDFSignatureDictionary(XmlPDFSignatureDictionary pdfSignatureDictionary1, XmlPDFSignatureDictionary pdfSignatureDictionary2) {
		assertEquals(pdfSignatureDictionary1.getSignerName(), pdfSignatureDictionary2.getSignerName());
		assertEquals(pdfSignatureDictionary1.getType(), pdfSignatureDictionary2.getType());
		assertEquals(pdfSignatureDictionary1.getFilter(), pdfSignatureDictionary2.getFilter());
		assertEquals(pdfSignatureDictionary1.getSubFilter(), pdfSignatureDictionary2.getSubFilter());
		assertEquals(pdfSignatureDictionary1.getContactInfo(), pdfSignatureDictionary2.getContactInfo());
		assertEquals(pdfSignatureDictionary1.getLocation(), pdfSignatureDictionary2.getLocation());
		assertEquals(pdfSignatureDictionary1.getReason(), pdfSignatureDictionary2.getReason());
		compareXmlByteRange(pdfSignatureDictionary1.getSignatureByteRange(), pdfSignatureDictionary2.getSignatureByteRange());
		compareXmlDocMDP(pdfSignatureDictionary1.getDocMDP(), pdfSignatureDictionary2.getDocMDP());
		compareXmlPDFLockDictionary(pdfSignatureDictionary1.getFieldMDP(), pdfSignatureDictionary2.getFieldMDP());
		assertEquals(pdfSignatureDictionary1.isConsistent(), pdfSignatureDictionary2.isConsistent());
	}

	private static void compareXmlByteRange(XmlByteRange signatureByteRange1, XmlByteRange signatureByteRange2) {
		assertEquals(signatureByteRange1 == null, signatureByteRange2 == null);
		if (signatureByteRange1 != null) {
			assertEquals(signatureByteRange1.getValue(), signatureByteRange2.getValue());
		}
	}

	private static void compareXmlDocMDP(XmlDocMDP docMDP1, XmlDocMDP docMDP2) {
		assertEquals(docMDP1 == null, docMDP2 == null);
		if (docMDP1 != null) {
			assertEquals(docMDP1.getPermissions(), docMDP2.getPermissions());
		}
	}

	private static void compareXmlModificationDetection(XmlModificationDetection modificationDetection1, XmlModificationDetection modificationDetection2) {
		assertEquals(modificationDetection1 == null, modificationDetection2 == null);
		if (modificationDetection1 != null) {
			compareModifications(modificationDetection1.getAnnotationOverlap(), modificationDetection2.getAnnotationOverlap());
			compareModifications(modificationDetection1.getVisualDifference(), modificationDetection2.getVisualDifference());
			compareModifications(modificationDetection1.getPageDifference(), modificationDetection2.getPageDifference());
			compareXmlObjectModifications(modificationDetection1.getObjectModifications(), modificationDetection2.getObjectModifications());
		}
	}

	private static void compareModifications(List<XmlModification> modifications1, List<XmlModification> modifications2) {
		assertEquals(Utils.collectionSize(modifications1), Utils.collectionSize(modifications2));
		if (Utils.isCollectionNotEmpty(modifications1)) {
			for (int i = 0; i < modifications1.size(); i++) {
				assertEquals(modifications1.get(i).getPage(), modifications2.get(i).getPage());
			}
		}
	}

	private static void compareXmlObjectModifications(XmlObjectModifications objectModifications1, XmlObjectModifications objectModifications2) {
		assertEquals(objectModifications1 == null, objectModifications2 == null);
		if (objectModifications1 != null) {
			compareObjectModifications(objectModifications1.getExtensionChanges(), objectModifications2.getExtensionChanges());
			compareObjectModifications(objectModifications1.getSignatureOrFormFill(), objectModifications2.getSignatureOrFormFill());
			compareObjectModifications(objectModifications1.getAnnotationChanges(), objectModifications2.getAnnotationChanges());
			compareObjectModifications(objectModifications1.getUndefined(), objectModifications2.getUndefined());
		}
	}

	private static void compareObjectModifications(List<XmlObjectModification> objectModifications1, List<XmlObjectModification> objectModifications2) {
		assertEquals(Utils.collectionSize(objectModifications1), Utils.collectionSize(objectModifications2));
		if (Utils.isCollectionNotEmpty(objectModifications1)) {
			for (int i = 0; i < objectModifications1.size(); i++) {
				compareObjectModification(objectModifications1.get(i), objectModifications2.get(i));
			}
		}
	}

	private static void compareObjectModification(XmlObjectModification xmlObjectModification1, XmlObjectModification xmlObjectModification2) {
		assertEquals(xmlObjectModification1.getAction(), xmlObjectModification2.getAction());
		assertEquals(xmlObjectModification1.getFieldName(), xmlObjectModification2.getFieldName());
		assertEquals(xmlObjectModification1.getType(), xmlObjectModification2.getType());
	}

	private static void compareXmlSignerDocumentRepresentations(XmlSignerDocumentRepresentations signerDocumentRepresentations1, XmlSignerDocumentRepresentations signerDocumentRepresentations2) {
		assertEquals(signerDocumentRepresentations1 == null, signerDocumentRepresentations2 == null);
		if (signerDocumentRepresentations1 != null) {
			assertEquals(signerDocumentRepresentations1.isHashOnly(), signerDocumentRepresentations2.isHashOnly());
			assertEquals(signerDocumentRepresentations1.isDocHashOnly(), signerDocumentRepresentations2.isDocHashOnly());
		}
	}

	private static void compareXmlFoundCertificates(XmlFoundCertificates foundCertificates1, XmlFoundCertificates foundCertificates2) {
		assertEquals(foundCertificates1 == null, foundCertificates2 == null);
		if (foundCertificates1 != null) {
			compareXmlRelatedCertificates(foundCertificates1.getRelatedCertificates(), foundCertificates2.getRelatedCertificates());
			compareXmlOrphanCertificates(foundCertificates1.getOrphanCertificates(), foundCertificates2.getOrphanCertificates());
		}
	}

	private static void compareXmlRelatedCertificates(List<XmlRelatedCertificate> relatedCertificates1, List<XmlRelatedCertificate> relatedCertificates2) {
		assertEquals(Utils.collectionSize(relatedCertificates1), Utils.collectionSize(relatedCertificates2));
		if (Utils.isCollectionNotEmpty(relatedCertificates1)) {
			for (int i = 0; i < relatedCertificates1.size(); i++) {
				compareXmlRelatedCertificate(relatedCertificates1.get(i), relatedCertificates2.get(i));
			}
		}
	}

	private static void compareXmlRelatedCertificate(XmlRelatedCertificate xmlRelatedCertificate1, XmlRelatedCertificate xmlRelatedCertificate2) {
		compareXmlFoundCertificate(xmlRelatedCertificate1, xmlRelatedCertificate2);
		compareXmlTokenIDREF(xmlRelatedCertificate1.getCertificate(), xmlRelatedCertificate2.getCertificate());
	}

	private static void compareXmlFoundCertificate(XmlFoundCertificate xmlFoundCertificate1, XmlFoundCertificate xmlFoundCertificate2) {
		assertEquals(xmlFoundCertificate1.getOrigins(), xmlFoundCertificate2.getOrigins());
		compareXmlCertificateRefs(xmlFoundCertificate1.getCertificateRefs(), xmlFoundCertificate2.getCertificateRefs());
	}

	private static void compareXmlCertificateRefs(List<XmlCertificateRef> certificateRefs1, List<XmlCertificateRef> certificateRefs2) {
		assertEquals(Utils.collectionSize(certificateRefs1), Utils.collectionSize(certificateRefs2));
		if (Utils.isCollectionNotEmpty(certificateRefs1)) {
			for (int i = 0; i < certificateRefs1.size(); i++) {
				compareXmlCertificateRef(certificateRefs1.get(i), certificateRefs2.get(i));
			}
		}
	}

	private static void compareXmlCertificateRef(XmlCertificateRef xmlCertificateRef1, XmlCertificateRef xmlCertificateRef2) {
		assertEquals(xmlCertificateRef1.getOrigin(), xmlCertificateRef2.getOrigin());
		compareXmlIssuerSerial(xmlCertificateRef1.getIssuerSerial(), xmlCertificateRef2.getIssuerSerial());
		compareXmDigestAlgoAndValue(xmlCertificateRef1.getDigestAlgoAndValue(), xmlCertificateRef2.getDigestAlgoAndValue());
		compareXmlSignerInfo(xmlCertificateRef1.getSerialInfo(), xmlCertificateRef2.getSerialInfo());
		assertEquals(xmlCertificateRef1.getX509Url(), xmlCertificateRef2.getX509Url());
	}

	private static void compareXmlIssuerSerial(XmlIssuerSerial issuerSerial1, XmlIssuerSerial issuerSerial2) {
		assertEquals(issuerSerial1 == null, issuerSerial2 == null);
		if (issuerSerial1 != null) {
			assertArrayEquals(issuerSerial1.getValue(), issuerSerial2.getValue());
			assertEquals(issuerSerial1.isMatch(), issuerSerial2.isMatch());
		}
	}

	private static void compareXmlOrphanCertificates(List<XmlOrphanCertificate> orphanCertificates1, List<XmlOrphanCertificate> orphanCertificates2) {
		assertEquals(Utils.collectionSize(orphanCertificates1), Utils.collectionSize(orphanCertificates2));
		if (Utils.isCollectionNotEmpty(orphanCertificates1)) {
			for (int i = 0; i < orphanCertificates1.size(); i++) {
				compareXmlOrphanCertificate(orphanCertificates1.get(i), orphanCertificates2.get(i));
			}
		}
	}

	private static void compareXmlOrphanCertificate(XmlOrphanCertificate xmlOrphanCertificate1, XmlOrphanCertificate xmlOrphanCertificate2) {
		compareXmlFoundCertificate(xmlOrphanCertificate1, xmlOrphanCertificate2);
		compareXmlTokenIDREF(xmlOrphanCertificate1.getToken(), xmlOrphanCertificate2.getToken());
	}

	private static void compareXmlFoundRevocations(XmlFoundRevocations foundRevocations1, XmlFoundRevocations foundRevocations2) {
		assertEquals(foundRevocations1 == null, foundRevocations2 == null);
		if (foundRevocations1 != null) {
			compareXmlRelatedRevocations(foundRevocations1.getRelatedRevocations(), foundRevocations2.getRelatedRevocations());
			compareXmlOrphanRevocations(foundRevocations1.getOrphanRevocations(), foundRevocations2.getOrphanRevocations());
		}
	}

	private static void compareXmlRelatedRevocations(List<XmlRelatedRevocation> relatedRevocations1, List<XmlRelatedRevocation> relatedRevocations2) {
		assertEquals(Utils.collectionSize(relatedRevocations1), Utils.collectionSize(relatedRevocations2));
		if (Utils.isCollectionNotEmpty(relatedRevocations1)) {
			for (int i = 0; i < relatedRevocations1.size(); i++) {
				compareXmlRelatedRevocation(relatedRevocations1.get(i), relatedRevocations2.get(i));
			}
		}
	}

	private static void compareXmlRelatedRevocation(XmlRelatedRevocation xmlRelatedRevocation1, XmlRelatedRevocation xmlRelatedRevocation2) {
		compareXmlFoundRevocation(xmlRelatedRevocation1, xmlRelatedRevocation2);
		compareXmlTokenIDREF(xmlRelatedRevocation1.getRevocation(), xmlRelatedRevocation2.getRevocation());
	}

	private static void compareXmlFoundRevocation(XmlFoundRevocation xmlFoundRevocation1, XmlFoundRevocation xmlFoundRevocation2) {
		assertEquals(xmlFoundRevocation1.getType(), xmlFoundRevocation2.getType());
		assertEquals(xmlFoundRevocation1.getOrigins(), xmlFoundRevocation2.getOrigins());
		compareXmlRevocationRefs(xmlFoundRevocation1.getRevocationRefs(), xmlFoundRevocation2.getRevocationRefs());
	}

	private static void compareXmlRevocationRefs(List<XmlRevocationRef> revocationRefs1, List<XmlRevocationRef> revocationRefs2) {
		assertEquals(Utils.collectionSize(revocationRefs1), Utils.collectionSize(revocationRefs2));
		if (Utils.isCollectionNotEmpty(revocationRefs1)) {
			for (int i = 0; i < revocationRefs1.size(); i++) {
				compareXmlRevocationRef(revocationRefs1.get(i), revocationRefs2.get(i));
			}
		}
	}

	private static void compareXmlRevocationRef(XmlRevocationRef xmlRevocationRef1, XmlRevocationRef xmlRevocationRef2) {
		assertEquals(xmlRevocationRef1.getOrigins(), xmlRevocationRef2.getOrigins());
		compareXmDigestAlgoAndValue(xmlRevocationRef1.getDigestAlgoAndValue(), xmlRevocationRef2.getDigestAlgoAndValue());
		assertDateEquals(xmlRevocationRef1.getProducedAt(), xmlRevocationRef2.getProducedAt());
		compareXmlSignerInfo(xmlRevocationRef1.getResponderId(), xmlRevocationRef2.getResponderId());
	}

	private static void compareXmlOrphanRevocations(List<XmlOrphanRevocation> orphanRevocations1, List<XmlOrphanRevocation> orphanRevocations2) {
		assertEquals(Utils.collectionSize(orphanRevocations1), Utils.collectionSize(orphanRevocations2));
		if (Utils.isCollectionNotEmpty(orphanRevocations1)) {
			for (int i = 0; i < orphanRevocations1.size(); i++) {
				compareXmlOrphanRevocation(orphanRevocations1.get(i), orphanRevocations2.get(i));
			}
		}
	}

	private static void compareXmlOrphanRevocation(XmlOrphanRevocation xmlOrphanRevocation1, XmlOrphanRevocation xmlOrphanRevocation2) {
		compareXmlFoundRevocation(xmlOrphanRevocation1, xmlOrphanRevocation2);
		compareXmlTokenIDREF(xmlOrphanRevocation1.getToken(), xmlOrphanRevocation2.getToken());
	}

	private static void compareXmlFoundTimestamps(List<XmlFoundTimestamp> foundTimestamps1, List<XmlFoundTimestamp> foundTimestamps2) {
		assertEquals(Utils.collectionSize(foundTimestamps1), Utils.collectionSize(foundTimestamps2));
		if (Utils.isCollectionNotEmpty(foundTimestamps1)) {
			for (int i = 0; i < foundTimestamps1.size(); i++) {
				compareXmlTokenIDREF(foundTimestamps1.get(i).getTimestamp(), foundTimestamps2.get(i).getTimestamp());
			}
		}
	}

	private static void compareXmlFoundEvidenceRecords(List<XmlFoundEvidenceRecord> foundEvidenceRecords1, List<XmlFoundEvidenceRecord> foundEvidenceRecords2) {
		assertEquals(Utils.collectionSize(foundEvidenceRecords1), Utils.collectionSize(foundEvidenceRecords2));
		if (Utils.isCollectionNotEmpty(foundEvidenceRecords1)) {
			for (int i = 0; i < foundEvidenceRecords1.size(); i++) {
				compareXmlTokenIDREF(foundEvidenceRecords1.get(i).getEvidenceRecord(), foundEvidenceRecords2.get(i).getEvidenceRecord());
			}
		}
	}

	private static void compareXmlSignatureScopes(List<XmlSignatureScope> signatureScopes1, List<XmlSignatureScope> signatureScopes2) {
		assertEquals(Utils.collectionSize(signatureScopes1), Utils.collectionSize(signatureScopes2));
		if (Utils.isCollectionNotEmpty(signatureScopes1)) {
			for (int i = 0; i < signatureScopes1.size(); i++) {
				compareXmlSignatureScope(signatureScopes1.get(i), signatureScopes2.get(i));
			}
		}
	}

	private static void compareXmlSignatureScope(XmlSignatureScope xmlSignatureScope1, XmlSignatureScope xmlSignatureScope2) {
		assertEquals(xmlSignatureScope1.getScope(), xmlSignatureScope2.getScope());
		assertEquals(xmlSignatureScope1.getName(), xmlSignatureScope2.getName());
		assertEquals(xmlSignatureScope1.getDescription(), xmlSignatureScope2.getDescription());
		assertEquals(xmlSignatureScope1.getTransformations(), xmlSignatureScope2.getTransformations());
		compareXmlTokenIDREF(xmlSignatureScope1.getSignerData(), xmlSignatureScope2.getSignerData());
	}

	private static void compareXmlSignatureDigestReference(XmlSignatureDigestReference signatureDigestReference1, XmlSignatureDigestReference signatureDigestReference2) {
		assertEquals(signatureDigestReference1.getCanonicalizationMethod(), signatureDigestReference2.getCanonicalizationMethod());
		assertEquals(signatureDigestReference1.getDigestMethod(), signatureDigestReference2.getDigestMethod());
		assertArrayEquals(signatureDigestReference1.getDigestValue(), signatureDigestReference2.getDigestValue());
	}

	private static void compareXmlEvidenceRecords(List<XmlEvidenceRecord> evidenceRecords1, List<XmlEvidenceRecord> evidenceRecords2) {
		assertEquals(Utils.collectionSize(evidenceRecords1), Utils.collectionSize(evidenceRecords2));
		if (Utils.isCollectionNotEmpty(evidenceRecords1)) {
			for (int i = 0; i < evidenceRecords1.size(); i++) {
				compareXmlEvidenceRecord(evidenceRecords1.get(i), evidenceRecords2.get(i));
			}
		}
	}

	private static void compareXmlEvidenceRecord(XmlEvidenceRecord xmlEvidenceRecord1, XmlEvidenceRecord xmlEvidenceRecord2) {
		compareXmlAbstractToken(xmlEvidenceRecord1, xmlEvidenceRecord2);
		assertEquals(xmlEvidenceRecord1.getDocumentName(), xmlEvidenceRecord2.getDocumentName());
		assertEquals(xmlEvidenceRecord1.getType(), xmlEvidenceRecord2.getType());
		assertEquals(xmlEvidenceRecord1.getOrigin(), xmlEvidenceRecord2.getOrigin());
		compareXmlStructuralValidation(xmlEvidenceRecord1.getStructuralValidation(), xmlEvidenceRecord2.getStructuralValidation());
		compareXmlDigestMatchers(xmlEvidenceRecord1.getDigestMatchers(), xmlEvidenceRecord2.getDigestMatchers());
		compareXmlFoundTimestamps(xmlEvidenceRecord1.getEvidenceRecordTimestamps(), xmlEvidenceRecord2.getEvidenceRecordTimestamps());
		compareXmlFoundCertificates(xmlEvidenceRecord1.getFoundCertificates(), xmlEvidenceRecord2.getFoundCertificates());
		compareXmlFoundRevocations(xmlEvidenceRecord1.getFoundRevocations(), xmlEvidenceRecord2.getFoundRevocations());
		compareXmlTimestampedObjects(xmlEvidenceRecord1.getTimestampedObjects(), xmlEvidenceRecord2.getTimestampedObjects());
		compareXmlSignatureScopes(xmlEvidenceRecord1.getEvidenceRecordScopes(), xmlEvidenceRecord2.getEvidenceRecordScopes());
		assertArrayEquals(xmlEvidenceRecord1.getBase64Encoded(), xmlEvidenceRecord2.getBase64Encoded());
		compareXmDigestAlgoAndValue(xmlEvidenceRecord1.getDigestAlgoAndValue(), xmlEvidenceRecord2.getDigestAlgoAndValue());
	}

	private static void compareXmlTimestampedObjects(List<XmlTimestampedObject> timestampedObjects1, List<XmlTimestampedObject> timestampedObjects2) {
		assertEquals(Utils.collectionSize(timestampedObjects1), Utils.collectionSize(timestampedObjects2));
		if (Utils.isCollectionNotEmpty(timestampedObjects1)) {
			for (int i = 0; i < timestampedObjects1.size(); i++) {
				compareXmlTimestampedObject(timestampedObjects1.get(i), timestampedObjects2.get(i));
			}
		}
	}

	private static void compareXmlTimestampedObject(XmlTimestampedObject xmlTimestampedObject1, XmlTimestampedObject xmlTimestampedObject2) {
		compareXmlTokenIDREF(xmlTimestampedObject1.getToken(), xmlTimestampedObject2.getToken());
		assertEquals(xmlTimestampedObject1.getCategory(), xmlTimestampedObject2.getCategory());
	}

	private static void compareXmlCertificates(List<XmlCertificate> certificates1, List<XmlCertificate> certificates2) {
		assertEquals(Utils.collectionSize(certificates1), Utils.collectionSize(certificates2));
		if (Utils.isCollectionNotEmpty(certificates1)) {
			for (int i = 0; i < certificates1.size(); i++) {
				compareXmlCertificate(certificates1.get(i), certificates2.get(i));
			}
		}
	}

	private static void compareXmlCertificate(XmlCertificate xmlCertificate1, XmlCertificate xmlCertificate2) {
		compareXmlAbstractToken(xmlCertificate1, xmlCertificate2);
		compareXmlDistinguishedNames(xmlCertificate1.getSubjectDistinguishedName(), xmlCertificate2.getSubjectDistinguishedName());
		compareXmlDistinguishedNames(xmlCertificate1.getIssuerDistinguishedName(), xmlCertificate2.getIssuerDistinguishedName());
		assertEquals(xmlCertificate1.getSerialNumber(), xmlCertificate2.getSerialNumber());
		assertEquals(xmlCertificate1.getSubjectSerialNumber(), xmlCertificate2.getSubjectSerialNumber());
		assertEquals(xmlCertificate1.getCommonName(), xmlCertificate2.getCommonName());
		assertEquals(xmlCertificate1.getLocality(), xmlCertificate2.getLocality());
		assertEquals(xmlCertificate1.getState(), xmlCertificate2.getState());
		assertEquals(xmlCertificate1.getCountryName(), xmlCertificate2.getCountryName());
		assertEquals(xmlCertificate1.getOrganizationIdentifier(), xmlCertificate2.getOrganizationIdentifier());
		assertEquals(xmlCertificate1.getOrganizationName(), xmlCertificate2.getOrganizationName());
		assertEquals(xmlCertificate1.getOrganizationalUnit(), xmlCertificate2.getOrganizationalUnit());
		assertEquals(xmlCertificate1.getTitle(), xmlCertificate2.getTitle());
		assertEquals(xmlCertificate1.getGivenName(), xmlCertificate2.getGivenName());
		assertEquals(xmlCertificate1.getSurname(), xmlCertificate2.getSurname());
		assertEquals(xmlCertificate1.getPseudonym(), xmlCertificate2.getPseudonym());
		assertEquals(xmlCertificate1.getEmail(), xmlCertificate2.getEmail());
		assertEquals(xmlCertificate1.getSources(), xmlCertificate2.getSources());
		assertDateEquals(xmlCertificate1.getNotAfter(), xmlCertificate2.getNotAfter());
		assertDateEquals(xmlCertificate1.getNotBefore(), xmlCertificate2.getNotBefore());
		assertEquals(xmlCertificate1.getPublicKeySize(), xmlCertificate2.getPublicKeySize());
		assertEquals(xmlCertificate1.getPublicKeyEncryptionAlgo(), xmlCertificate2.getPublicKeyEncryptionAlgo());
		compareCertificateChain(xmlCertificate1.getCertificateChain(), xmlCertificate2.getCertificateChain());
		compareXmlTrusted(xmlCertificate1.getTrusted(), xmlCertificate2.getTrusted());
		assertEquals(xmlCertificate1.isSelfSigned(), xmlCertificate2.isSelfSigned());
		compareXmlCertificateExtensions(xmlCertificate1.getCertificateExtensions(), xmlCertificate2.getCertificateExtensions());
		compareXmlTrustServiceProviders(xmlCertificate1.getTrustServiceProviders(), xmlCertificate2.getTrustServiceProviders());
		compareXmlCertificateRevocations(xmlCertificate1.getRevocations(), xmlCertificate2.getRevocations());
		assertArrayEquals(xmlCertificate1.getBase64Encoded(), xmlCertificate2.getBase64Encoded());
		compareXmDigestAlgoAndValue(xmlCertificate1.getDigestAlgoAndValue(), xmlCertificate2.getDigestAlgoAndValue());
	}

	private static void compareXmlDistinguishedNames(List<XmlDistinguishedName> subjectDistinguishedNames1, List<XmlDistinguishedName> subjectDistinguishedNames2) {
		assertEquals(Utils.collectionSize(subjectDistinguishedNames1), Utils.collectionSize(subjectDistinguishedNames2));
		if (Utils.isCollectionNotEmpty(subjectDistinguishedNames1)) {
			for (int i = 0; i < subjectDistinguishedNames1.size(); i++) {
				compareXmlDistinguishedName(subjectDistinguishedNames1.get(i), subjectDistinguishedNames2.get(i));
			}
		}
	}

	private static void compareXmlDistinguishedName(XmlDistinguishedName xmlDistinguishedName1, XmlDistinguishedName xmlDistinguishedName2) {
		assertEquals(xmlDistinguishedName1.getValue(), xmlDistinguishedName2.getValue());
		assertEquals(xmlDistinguishedName1.getFormat(), xmlDistinguishedName2.getFormat());
	}

	private static void compareXmlTrusted(XmlTrusted trusted1, XmlTrusted trusted2) {
		assertEquals(trusted1 == null, trusted2 == null);
		if (trusted1 != null) {
			assertEquals(trusted1.isValue(), trusted2.isValue());
			assertDateEquals(trusted1.getStartDate(), trusted2.getStartDate());
			assertDateEquals(trusted1.getSunsetDate(), trusted2.getSunsetDate());
		}
	}

	private static void compareXmlCertificateExtensions(List<XmlCertificateExtension> certificateExtensions1, List<XmlCertificateExtension> certificateExtensions2) {
		assertEquals(Utils.collectionSize(certificateExtensions1), Utils.collectionSize(certificateExtensions2));
		if (Utils.isCollectionNotEmpty(certificateExtensions1)) {
			for (int i = 0; i < certificateExtensions1.size(); i++) {
				compareXmlCertificateExtension(certificateExtensions1.get(i), certificateExtensions2.get(i));
			}
		}
	}

	private static void compareXmlCertificateExtension(XmlCertificateExtension xmlCertificateExtension1, XmlCertificateExtension xmlCertificateExtension2) {
		assertEquals(xmlCertificateExtension1.getClass(), xmlCertificateExtension2.getClass());
		if (xmlCertificateExtension1 instanceof XmlKeyUsages) {
			compareXmlKeyUsages((XmlKeyUsages) xmlCertificateExtension1, (XmlKeyUsages) xmlCertificateExtension2);
		} else if (xmlCertificateExtension1 instanceof XmlExtendedKeyUsages) {
			compareXmlExtendedKeyUsages((XmlExtendedKeyUsages) xmlCertificateExtension1, (XmlExtendedKeyUsages) xmlCertificateExtension2);
		} else if (xmlCertificateExtension1 instanceof XmlCertificatePolicies) {
			compareXmlCertificatePolicies((XmlCertificatePolicies) xmlCertificateExtension1, (XmlCertificatePolicies) xmlCertificateExtension2);
		} else if (xmlCertificateExtension1 instanceof XmlSubjectAlternativeNames) {
			compareXmlSubjectAlternativeNames((XmlSubjectAlternativeNames) xmlCertificateExtension1, (XmlSubjectAlternativeNames) xmlCertificateExtension2);
		} else if (xmlCertificateExtension1 instanceof XmlBasicConstraints) {
			compareXmlBasicConstraints((XmlBasicConstraints) xmlCertificateExtension1, (XmlBasicConstraints) xmlCertificateExtension2);
		} else if (xmlCertificateExtension1 instanceof XmlPolicyConstraints) {
			compareXmlPolicyConstraints((XmlPolicyConstraints) xmlCertificateExtension1, (XmlPolicyConstraints) xmlCertificateExtension2);
		} else if (xmlCertificateExtension1 instanceof XmlInhibitAnyPolicy) {
			compareXmlInhibitAnyPolicy((XmlInhibitAnyPolicy) xmlCertificateExtension1, (XmlInhibitAnyPolicy) xmlCertificateExtension2);
		} else if (xmlCertificateExtension1 instanceof XmlNameConstraints) {
			compareXmlNameConstraints((XmlNameConstraints) xmlCertificateExtension1, (XmlNameConstraints) xmlCertificateExtension2);
		} else if (xmlCertificateExtension1 instanceof XmlCRLDistributionPoints) { // or FreshestCRL
			compareXmlCRLDistributionPoints((XmlCRLDistributionPoints) xmlCertificateExtension1, (XmlCRLDistributionPoints) xmlCertificateExtension2);
		} else if (xmlCertificateExtension1 instanceof XmlAuthorityKeyIdentifier) {
			compareXmlAuthorityKeyIdentifier((XmlAuthorityKeyIdentifier) xmlCertificateExtension1, (XmlAuthorityKeyIdentifier) xmlCertificateExtension2);
		} else if (xmlCertificateExtension1 instanceof XmlSubjectKeyIdentifier) {
			compareXmlSubjectKeyIdentifier((XmlSubjectKeyIdentifier) xmlCertificateExtension1, (XmlSubjectKeyIdentifier) xmlCertificateExtension2);
		} else if (xmlCertificateExtension1 instanceof XmlAuthorityInformationAccess) {
			compareXmlAuthorityInformationAccess((XmlAuthorityInformationAccess) xmlCertificateExtension1, (XmlAuthorityInformationAccess) xmlCertificateExtension2);
		} else if (xmlCertificateExtension1 instanceof XmlIdPkixOcspNoCheck) {
			compareXmlIdPkixOcspNoCheck((XmlIdPkixOcspNoCheck) xmlCertificateExtension1, (XmlIdPkixOcspNoCheck) xmlCertificateExtension2);
		} else if (xmlCertificateExtension1 instanceof XmlValAssuredShortTermCertificate) {
			compareXmlValAssuredShortTermCertificate((XmlValAssuredShortTermCertificate) xmlCertificateExtension1, (XmlValAssuredShortTermCertificate) xmlCertificateExtension2);
		} else if (xmlCertificateExtension1 instanceof XmlNoRevAvail) {
			compareXmlNoRevAvail((XmlNoRevAvail) xmlCertificateExtension1, (XmlNoRevAvail) xmlCertificateExtension2);
		} else if (xmlCertificateExtension1 instanceof XmlQcStatements) {
			compareXmlQcStatements((XmlQcStatements) xmlCertificateExtension1, (XmlQcStatements) xmlCertificateExtension2);
		} else { // OtherExtension
			compareAbstractCertificateExtension(xmlCertificateExtension1, xmlCertificateExtension2);
		}
	}

	private static void compareXmlKeyUsages(XmlKeyUsages xmlKeyUsages1, XmlKeyUsages xmlKeyUsages2) {
		compareAbstractCertificateExtension(xmlKeyUsages1, xmlKeyUsages2);
		assertEquals(xmlKeyUsages1.getKeyUsageBit(), xmlKeyUsages2.getKeyUsageBit());
	}

	private static void compareAbstractCertificateExtension(XmlCertificateExtension xmlCertificateExtension1, XmlCertificateExtension xmlCertificateExtension2) {
		assertArrayEquals(xmlCertificateExtension1.getOctets(), xmlCertificateExtension2.getOctets());
		assertEquals(xmlCertificateExtension1.getOID(), xmlCertificateExtension2.getOID());
		assertEquals(xmlCertificateExtension1.getDescription(), xmlCertificateExtension2.getDescription());
		assertEquals(xmlCertificateExtension1.isCritical(), xmlCertificateExtension2.isCritical());
	}

	private static void compareXmlExtendedKeyUsages(XmlExtendedKeyUsages extension1, XmlExtendedKeyUsages extension2) {
		compareAbstractCertificateExtension(extension1, extension2);
		compareXmlOIDs(extension1.getExtendedKeyUsageOid(), extension2.getExtendedKeyUsageOid());
	}

	private static void compareXmlCertificatePolicies(XmlCertificatePolicies extension1, XmlCertificatePolicies extension2) {
		compareAbstractCertificateExtension(extension1, extension2);
		compareXmlCertificatePoliciesExtensions(extension1.getCertificatePolicy(), extension2.getCertificatePolicy());
	}

	private static void compareXmlCertificatePoliciesExtensions(List<XmlCertificatePolicy> certificatePolicy1, List<XmlCertificatePolicy> certificatePolicy2) {
		assertEquals(Utils.collectionSize(certificatePolicy1), Utils.collectionSize(certificatePolicy2));
		if (Utils.isCollectionNotEmpty(certificatePolicy1)) {
			for (int i = 0; i < certificatePolicy1.size(); i++) {
				compareXmlCertificatePoliciesExtension(certificatePolicy1.get(i), certificatePolicy2.get(i));
			}
		}
	}

	private static void compareXmlCertificatePoliciesExtension(XmlCertificatePolicy xmlCertificatePolicy1, XmlCertificatePolicy xmlCertificatePolicy2) {
		compareXmlOID(xmlCertificatePolicy1, xmlCertificatePolicy2);
		assertEquals(xmlCertificatePolicy1.getCpsUrl(), xmlCertificatePolicy2.getCpsUrl());
	}

	private static void compareXmlOIDs(List<XmlOID> xmlOIDs1, List<XmlOID> xmlOIDs2) {
		assertEquals(Utils.collectionSize(xmlOIDs1), Utils.collectionSize(xmlOIDs2));
		if (Utils.isCollectionNotEmpty(xmlOIDs1)) {
			for (int i = 0; i < xmlOIDs1.size(); i++) {
				compareXmlOID(xmlOIDs1.get(i), xmlOIDs2.get(i));
			}
		}
	}

	private static void compareXmlOID(XmlOID xmlOID1, XmlOID xmlOID2) {
		assertEquals(xmlOID1 == null, xmlOID2 == null);
		if (xmlOID1 != null) {
			assertEquals(xmlOID1.getValue(), xmlOID2.getValue());
			assertEquals(xmlOID1.getDescription(), xmlOID2.getDescription());
		}
	}

	private static void compareXmlSubjectAlternativeNames(XmlSubjectAlternativeNames extension1, XmlSubjectAlternativeNames extension2) {
		compareAbstractCertificateExtension(extension1, extension2);
		compareXmlGeneralNames(extension1.getSubjectAlternativeName(), extension2.getSubjectAlternativeName());
	}

	private static void compareXmlBasicConstraints(XmlBasicConstraints extension1, XmlBasicConstraints extension2) {
		compareAbstractCertificateExtension(extension1, extension2);
		assertEquals(extension1.isCA(), extension2.isCA());
		assertEquals(extension1.getPathLenConstraint(), extension2.getPathLenConstraint());
	}

	private static void compareXmlPolicyConstraints(XmlPolicyConstraints extension1, XmlPolicyConstraints extension2) {
		compareAbstractCertificateExtension(extension1, extension2);
		assertEquals(extension1.getRequireExplicitPolicy(), extension2.getRequireExplicitPolicy());
		assertEquals(extension1.getInhibitPolicyMapping(), extension2.getInhibitPolicyMapping());
	}

	private static void compareXmlInhibitAnyPolicy(XmlInhibitAnyPolicy extension1, XmlInhibitAnyPolicy extension2) {
		compareAbstractCertificateExtension(extension1, extension2);
		assertEquals(extension1.getValue(), extension2.getValue());
	}

	private static void compareXmlNameConstraints(XmlNameConstraints extension1, XmlNameConstraints extension2) {
		compareAbstractCertificateExtension(extension1, extension2);
		compareGeneralSubtrees(extension1.getPermittedSubtrees(), extension2.getPermittedSubtrees());
		compareGeneralSubtrees(extension1.getExcludedSubtrees(), extension2.getExcludedSubtrees());
	}

	private static void compareGeneralSubtrees(List<XmlGeneralSubtree> permittedSubtrees1, List<XmlGeneralSubtree> permittedSubtrees2) {
		assertEquals(Utils.collectionSize(permittedSubtrees1), Utils.collectionSize(permittedSubtrees2));
		if (Utils.isCollectionNotEmpty(permittedSubtrees1)) {
			for (int i = 0; i < permittedSubtrees1.size(); i++) {
				compareXmlGeneralSubtree(permittedSubtrees1.get(i), permittedSubtrees2.get(i));
			}
		}
	}

	private static void compareXmlGeneralSubtree(XmlGeneralSubtree xmlGeneralSubtree1, XmlGeneralSubtree xmlGeneralSubtree2) {
		compareXmlGeneralName(xmlGeneralSubtree1, xmlGeneralSubtree2);
		assertEquals(xmlGeneralSubtree1.getMinimum(), xmlGeneralSubtree2.getMinimum());
		assertEquals(xmlGeneralSubtree1.getMaximum(), xmlGeneralSubtree2.getMaximum());
	}

	private static void compareXmlGeneralNames(List<XmlGeneralName> xmlGeneralNames1, List<XmlGeneralName> xmlGeneralNames2) {
		assertEquals(Utils.collectionSize(xmlGeneralNames1), Utils.collectionSize(xmlGeneralNames2));
		if (Utils.isCollectionNotEmpty(xmlGeneralNames1)) {
			for (int i = 0; i < xmlGeneralNames1.size(); i++) {
				compareXmlGeneralName(xmlGeneralNames1.get(i), xmlGeneralNames2.get(i));
			}
		}
	}

	private static void compareXmlGeneralName(XmlGeneralName xmlGeneralName1, XmlGeneralName xmlGeneralName2) {
		assertEquals(xmlGeneralName1.getValue(), xmlGeneralName2.getValue());
		assertEquals(xmlGeneralName1.getType(), xmlGeneralName2.getType());
	}

	private static void compareXmlCRLDistributionPoints(XmlCRLDistributionPoints extension1, XmlCRLDistributionPoints extension2) {
		compareAbstractCertificateExtension(extension1, extension2);
		assertEquals(extension1.getCrlUrl(), extension2.getCrlUrl());
	}

	private static void compareXmlAuthorityKeyIdentifier(XmlAuthorityKeyIdentifier extension1, XmlAuthorityKeyIdentifier extension2) {
		compareAbstractCertificateExtension(extension1, extension2);
		assertArrayEquals(extension1.getKeyIdentifier(), extension2.getKeyIdentifier());
		assertArrayEquals(extension1.getAuthorityCertIssuerSerial(), extension2.getAuthorityCertIssuerSerial());
	}

	private static void compareXmlSubjectKeyIdentifier(XmlSubjectKeyIdentifier extension1, XmlSubjectKeyIdentifier extension2) {
		compareAbstractCertificateExtension(extension1, extension2);
		assertArrayEquals(extension1.getSki(), extension2.getSki());
	}

	private static void compareXmlAuthorityInformationAccess(XmlAuthorityInformationAccess extension1, XmlAuthorityInformationAccess extension2) {
		compareAbstractCertificateExtension(extension1, extension2);
		assertEquals(extension1.getCaIssuersUrls(), extension2.getCaIssuersUrls());
		assertEquals(extension1.getOcspUrls(), extension2.getOcspUrls());
	}

	private static void compareXmlIdPkixOcspNoCheck(XmlIdPkixOcspNoCheck extension1, XmlIdPkixOcspNoCheck extension2) {
		compareAbstractCertificateExtension(extension1, extension2);
		assertEquals(extension1.isPresent(), extension2.isPresent());
	}

	private static void compareXmlValAssuredShortTermCertificate(XmlValAssuredShortTermCertificate extension1, XmlValAssuredShortTermCertificate extension2) {
		compareAbstractCertificateExtension(extension1, extension2);
		assertEquals(extension1.isPresent(), extension2.isPresent());
	}

	private static void compareXmlNoRevAvail(XmlNoRevAvail extension1, XmlNoRevAvail extension2) {
		compareAbstractCertificateExtension(extension1, extension2);
		assertEquals(extension1.isPresent(), extension2.isPresent());
	}

	private static void compareXmlQcStatements(XmlQcStatements qcStatements1, XmlQcStatements qcStatements2) {
		compareAbstractCertificateExtension(qcStatements1, qcStatements2);
		compareXmlQcCompliance(qcStatements1.getQcCompliance(), qcStatements2.getQcCompliance());
		compareXmlQcEuLimitValue(qcStatements1.getQcEuLimitValue(), qcStatements2.getQcEuLimitValue());
		assertEquals(qcStatements1.getQcEuRetentionPeriod(), qcStatements2.getQcEuRetentionPeriod());
		compareXmlQcSSCD(qcStatements1.getQcSSCD(), qcStatements2.getQcSSCD());
		compareXmlLangAndValues(qcStatements1.getQcEuPDS(), qcStatements2.getQcEuPDS());
		compareXmlQcTypes(qcStatements1.getQcTypes(), qcStatements2.getQcTypes());
		assertEquals(qcStatements1.getQcCClegislation(), qcStatements2.getQcCClegislation());
		compareXmlOID(qcStatements1.getSemanticsIdentifier(), qcStatements2.getSemanticsIdentifier());
		compareXmlPSD2QcInfo(qcStatements1.getPSD2QcInfo(), qcStatements2.getPSD2QcInfo());
		compareXmlOIDs(qcStatements1.getOtherOIDs(), qcStatements2.getOtherOIDs());
		compareXmlMRACertificateMapping(qcStatements1.getMRACertificateMapping(), qcStatements2.getMRACertificateMapping());
		assertEquals(qcStatements1.isEnactedMRA(), qcStatements2.isEnactedMRA());
	}

	private static void compareXmlQcCompliance(XmlQcCompliance qcCompliance1, XmlQcCompliance qcCompliance2) {
		assertEquals(qcCompliance1 == null, qcCompliance2 == null);
		if (qcCompliance1 != null) {
			assertEquals(qcCompliance1.isPresent(), qcCompliance2.isPresent());
		}
	}

	private static void compareXmlQcEuLimitValue(XmlQcEuLimitValue qcEuLimitValue1, XmlQcEuLimitValue qcEuLimitValue2) {
		assertEquals(qcEuLimitValue1 == null, qcEuLimitValue2 == null);
		if (qcEuLimitValue1 != null) {
			assertEquals(qcEuLimitValue1.getCurrency(), qcEuLimitValue2.getCurrency());
			assertEquals(qcEuLimitValue1.getAmount(), qcEuLimitValue2.getAmount());
			assertEquals(qcEuLimitValue1.getExponent(), qcEuLimitValue2.getExponent());
		}
	}

	private static void compareXmlQcSSCD(XmlQcSSCD qcSSCD1, XmlQcSSCD qcSSCD2) {
		assertEquals(qcSSCD1 == null, qcSSCD2 == null);
		if (qcSSCD1 != null) {
			assertEquals(qcSSCD1.isPresent(), qcSSCD2.isPresent());
		}
	}

	private static void compareXmlLangAndValues(List<XmlLangAndValue> qcEuPDS1, List<XmlLangAndValue> qcEuPDS2) {
		assertEquals(Utils.collectionSize(qcEuPDS1), Utils.collectionSize(qcEuPDS2));
		if (Utils.isCollectionNotEmpty(qcEuPDS1)) {
			for (int i = 0; i < qcEuPDS1.size(); i++) {
				compareXmlLangAndValue(qcEuPDS1.get(i), qcEuPDS2.get(i));
			}
		}
	}

	private static void compareXmlLangAndValue(XmlLangAndValue xmlLangAndValue1, XmlLangAndValue xmlLangAndValue2) {
		assertEquals(xmlLangAndValue1.getValue(), xmlLangAndValue2.getValue());
		assertEquals(xmlLangAndValue1.getLang(), xmlLangAndValue2.getLang());
	}

	private static void compareXmlQcTypes(List<XmlOID> qcTypes1, List<XmlOID> qcTypes2) {
		assertEquals(Utils.collectionSize(qcTypes1), Utils.collectionSize(qcTypes2));
		if (Utils.isCollectionNotEmpty(qcTypes1)) {
			for (int i = 0; i < qcTypes1.size(); i++) {
				compareXmlOID(qcTypes1.get(i), qcTypes2.get(i));
			}
		}
	}

	private static void compareXmlPSD2QcInfo(XmlPSD2QcInfo psd2QcInfo1, XmlPSD2QcInfo psd2QcInfo2) {
		assertEquals(psd2QcInfo1 == null, psd2QcInfo2 == null);
		if (psd2QcInfo1 != null) {
			compareXmlRolesOfPSPs(psd2QcInfo1.getRolesOfPSP(), psd2QcInfo2.getRolesOfPSP());
			assertEquals(psd2QcInfo1.getNcaName(), psd2QcInfo2.getNcaName());
			assertEquals(psd2QcInfo1.getNcaId(), psd2QcInfo2.getNcaId());
		}
	}

	private static void compareXmlRolesOfPSPs(List<XmlRoleOfPSP> rolesOfPSP1, List<XmlRoleOfPSP> rolesOfPSP2) {
		assertEquals(Utils.collectionSize(rolesOfPSP1), Utils.collectionSize(rolesOfPSP2));
		if (Utils.isCollectionNotEmpty(rolesOfPSP1)) {
			for (int i = 0; i < rolesOfPSP1.size(); i++) {
				compareXmlRoleOfPSP(rolesOfPSP1.get(i), rolesOfPSP2.get(i));
			}
		}
	}

	private static void compareXmlRoleOfPSP(XmlRoleOfPSP xmlRoleOfPSP1, XmlRoleOfPSP xmlRoleOfPSP2) {
		compareXmlOID(xmlRoleOfPSP1.getOid(), xmlRoleOfPSP2.getOid());
		assertEquals(xmlRoleOfPSP1.getName(), xmlRoleOfPSP2.getName());
	}

	private static void compareXmlMRACertificateMapping(XmlMRACertificateMapping mraCertificateMapping1, XmlMRACertificateMapping mraCertificateMapping2) {
		assertEquals(mraCertificateMapping1 == null, mraCertificateMapping2 == null);
		if (mraCertificateMapping1 != null) {
			compareXmlTrustServiceEquivalenceInformation(mraCertificateMapping1.getTrustServiceEquivalenceInformation(), mraCertificateMapping2.getTrustServiceEquivalenceInformation());
			compareXmlOriginalThirdCountryQcStatementsMapping(mraCertificateMapping1.getOriginalThirdCountryMapping(), mraCertificateMapping2.getOriginalThirdCountryMapping());
		}
		}

	private static void compareXmlTrustServiceEquivalenceInformation(XmlTrustServiceEquivalenceInformation trustServiceEquivalenceInformation1, XmlTrustServiceEquivalenceInformation trustServiceEquivalenceInformation2) {
		assertEquals(trustServiceEquivalenceInformation1.getTrustServiceLegalIdentifier(), trustServiceEquivalenceInformation2.getTrustServiceLegalIdentifier());
		compareXmlCertificateContentEquivalences(trustServiceEquivalenceInformation1.getCertificateContentEquivalenceList(), trustServiceEquivalenceInformation2.getCertificateContentEquivalenceList());
	}

	private static void compareXmlCertificateContentEquivalences(List<XmlCertificateContentEquivalence> certificateContentEquivalences1, List<XmlCertificateContentEquivalence> certificateContentEquivalences2) {
		assertEquals(Utils.collectionSize(certificateContentEquivalences1), Utils.collectionSize(certificateContentEquivalences2));
		if (Utils.isCollectionNotEmpty(certificateContentEquivalences1)) {
			for (int i = 0; i < certificateContentEquivalences1.size(); i++) {
				compareXmlCertificateContentEquivalence(certificateContentEquivalences1.get(i), certificateContentEquivalences2.get(i));
			}
		}
	}

	private static void compareXmlCertificateContentEquivalence(XmlCertificateContentEquivalence xmlCertificateContentEquivalence1, XmlCertificateContentEquivalence xmlCertificateContentEquivalence2) {
		assertEquals(xmlCertificateContentEquivalence1.getUri(), xmlCertificateContentEquivalence2.getUri());
		assertEquals(xmlCertificateContentEquivalence1.isEnacted(), xmlCertificateContentEquivalence2.isEnacted());
	}

	private static void compareXmlOriginalThirdCountryQcStatementsMapping(XmlOriginalThirdCountryQcStatementsMapping originalThirdCountryMapping1, XmlOriginalThirdCountryQcStatementsMapping originalThirdCountryMapping2) {
		compareXmlQcCompliance(originalThirdCountryMapping1.getQcCompliance(), originalThirdCountryMapping2.getQcCompliance());
		compareXmlQcSSCD(originalThirdCountryMapping1.getQcSSCD(), originalThirdCountryMapping2.getQcSSCD());
		compareXmlQcTypes(originalThirdCountryMapping1.getQcTypes(), originalThirdCountryMapping2.getQcTypes());
		assertEquals(originalThirdCountryMapping1.getQcCClegislation(), originalThirdCountryMapping2.getQcCClegislation());
		compareXmlOIDs(originalThirdCountryMapping1.getOtherOIDs(), originalThirdCountryMapping2.getOtherOIDs());
	}

	private static void compareXmlTrustServiceProviders(List<XmlTrustServiceProvider> trustServiceProviders1, List<XmlTrustServiceProvider> trustServiceProviders2) {
		assertEquals(Utils.collectionSize(trustServiceProviders1), Utils.collectionSize(trustServiceProviders2));
		if (Utils.isCollectionNotEmpty(trustServiceProviders1)) {
			for (int i = 0; i < trustServiceProviders1.size(); i++) {
				compareXmlTrustServiceProvider(trustServiceProviders1.get(i), trustServiceProviders2.get(i));
			}
		}
	}

	private static void compareXmlTrustServiceProvider(XmlTrustServiceProvider xmlTrustServiceProvider1, XmlTrustServiceProvider xmlTrustServiceProvider2) {
		compareXmlLangAndValues(xmlTrustServiceProvider1.getTSPNames(), xmlTrustServiceProvider2.getTSPNames());
		compareXmlLangAndValues(xmlTrustServiceProvider1.getTSPTradeNames(), xmlTrustServiceProvider2.getTSPTradeNames());
		assertEquals(xmlTrustServiceProvider1.getTSPRegistrationIdentifiers(), xmlTrustServiceProvider2.getTSPRegistrationIdentifiers());
		compareXmlTrustServices(xmlTrustServiceProvider1.getTrustServices(), xmlTrustServiceProvider2.getTrustServices());
		compareXmlTLIDREF(xmlTrustServiceProvider1.getTL(), xmlTrustServiceProvider2.getTL());
		compareXmlTLIDREF(xmlTrustServiceProvider1.getLOTL(), xmlTrustServiceProvider2.getLOTL());
	}

	private static void compareXmlTrustServices(List<XmlTrustService> trustServices1, List<XmlTrustService> trustServices2) {
		assertEquals(Utils.collectionSize(trustServices1), Utils.collectionSize(trustServices2));
		if (Utils.isCollectionNotEmpty(trustServices1)) {
			for (int i = 0; i < trustServices1.size(); i++) {
				compareXmlTrustService(trustServices1.get(i), trustServices2.get(i));
			}
		}
	}

	private static void compareXmlTrustService(XmlTrustService xmlTrustService1, XmlTrustService xmlTrustService2) {
		compareXmlLangAndValues(xmlTrustService1.getServiceNames(), xmlTrustService2.getServiceNames());
		assertEquals(xmlTrustService1.getServiceType(), xmlTrustService2.getServiceType());
		assertEquals(xmlTrustService1.getStatus(), xmlTrustService2.getStatus());
		assertDateEquals(xmlTrustService1.getStartDate(), xmlTrustService2.getStartDate());
		assertDateEquals(xmlTrustService1.getEndDate(), xmlTrustService2.getEndDate());
		compareXmlQualifiers(xmlTrustService1.getCapturedQualifiers(), xmlTrustService2.getCapturedQualifiers());
		assertEquals(xmlTrustService1.getAdditionalServiceInfoUris(), xmlTrustService2.getAdditionalServiceInfoUris());
		assertEquals(xmlTrustService1.getServiceSupplyPoints(), xmlTrustService2.getServiceSupplyPoints());
		assertDateEquals(xmlTrustService1.getExpiredCertsRevocationInfo(), xmlTrustService2.getExpiredCertsRevocationInfo());
		compareXmlTrustServiceMapping(xmlTrustService1.getMRATrustServiceMapping(), xmlTrustService2.getMRATrustServiceMapping());
		compareXmlTokenIDREF(xmlTrustService1.getServiceDigitalIdentifier(), xmlTrustService2.getServiceDigitalIdentifier());
		assertEquals(xmlTrustService1.isEnactedMRA(), xmlTrustService2.isEnactedMRA());
	}

	private static void compareXmlQualifiers(List<XmlQualifier> capturedQualifiers1, List<XmlQualifier> capturedQualifiers2) {
		assertEquals(Utils.collectionSize(capturedQualifiers1), Utils.collectionSize(capturedQualifiers2));
		if (Utils.isCollectionNotEmpty(capturedQualifiers1)) {
			for (int i = 0; i < capturedQualifiers1.size(); i++) {
				compareXmlQualifier(capturedQualifiers1.get(i), capturedQualifiers2.get(i));
			}
		}
	}

	private static void compareXmlQualifier(XmlQualifier xmlQualifier1, XmlQualifier xmlQualifier2) {
		assertEquals(xmlQualifier1.getValue(), xmlQualifier2.getValue());
		assertEquals(xmlQualifier1.isCritical(), xmlQualifier2.isCritical());
	}

	private static void compareXmlTrustServiceMapping(XmlMRATrustServiceMapping mraTrustServiceMapping1, XmlMRATrustServiceMapping mraTrustServiceMapping2) {
		assertEquals(mraTrustServiceMapping1 == null, mraTrustServiceMapping2 == null);
		if (mraTrustServiceMapping1 != null) {
			assertEquals(mraTrustServiceMapping1.getTrustServiceLegalIdentifier(), mraTrustServiceMapping2.getTrustServiceLegalIdentifier());
			assertDateEquals(mraTrustServiceMapping1.getEquivalenceStatusStartingTime(), mraTrustServiceMapping2.getEquivalenceStatusStartingTime());
			assertDateEquals(mraTrustServiceMapping1.getEquivalenceStatusEndingTime(), mraTrustServiceMapping2.getEquivalenceStatusEndingTime());
			compareXmlOriginalThirdCountryTrustServiceMapping(mraTrustServiceMapping1.getOriginalThirdCountryMapping(), mraTrustServiceMapping2.getOriginalThirdCountryMapping());
		}
	}

	private static void compareXmlOriginalThirdCountryTrustServiceMapping(
			XmlOriginalThirdCountryTrustServiceMapping originalThirdCountryMapping1, XmlOriginalThirdCountryTrustServiceMapping originalThirdCountryMapping2) {
		assertEquals(originalThirdCountryMapping1 == null, originalThirdCountryMapping2 == null);
		if (originalThirdCountryMapping1 != null) {
			assertEquals(originalThirdCountryMapping1.getServiceType(), originalThirdCountryMapping2.getServiceType());
			assertEquals(originalThirdCountryMapping1.getStatus(), originalThirdCountryMapping2.getStatus());
			compareXmlQualifiers(originalThirdCountryMapping1.getCapturedQualifiers(), originalThirdCountryMapping2.getCapturedQualifiers());
			assertEquals(originalThirdCountryMapping1.getAdditionalServiceInfoUris(), originalThirdCountryMapping2.getAdditionalServiceInfoUris());
		}
	}

	private static void compareXmlTLIDREF(XmlTrustedList tl1, XmlTrustedList tl2) {
		assertEquals(tl1 == null, tl2 == null);
		if (tl1 != null) {
			assertEquals(tl1.getId(), tl2.getId());
		}
	}

	private static void compareXmlCertificateRevocations(List<XmlCertificateRevocation> revocations1, List<XmlCertificateRevocation> revocations2) {
		assertEquals(Utils.collectionSize(revocations1), Utils.collectionSize(revocations2));
		if (Utils.isCollectionNotEmpty(revocations1)) {
			for (int i = 0; i < revocations1.size(); i++) {
				compareXmlCertificateRevocation(revocations1.get(i), revocations2.get(i));
			}
		}
	}

	private static void compareXmlCertificateRevocation(XmlCertificateRevocation xmlCertificateRevocation1, XmlCertificateRevocation xmlCertificateRevocation2) {
		assertEquals(xmlCertificateRevocation1.getStatus(), xmlCertificateRevocation2.getStatus());
		assertEquals(xmlCertificateRevocation1.getReason(), xmlCertificateRevocation2.getReason());
		assertDateEquals(xmlCertificateRevocation1.getRevocationDate(), xmlCertificateRevocation2.getRevocationDate());
		compareXmlTokenIDREF(xmlCertificateRevocation1.getRevocation(), xmlCertificateRevocation2.getRevocation());
	}

	private static void compareXmlRevocations(List<XmlRevocation> revocations1, List<XmlRevocation> revocations2) {
		assertEquals(Utils.collectionSize(revocations1), Utils.collectionSize(revocations2));
		if (Utils.isCollectionNotEmpty(revocations1)) {
			for (int i = 0; i < revocations1.size(); i++) {
				compareXmlRevocation(revocations1.get(i), revocations2.get(i));
			}
		}
	}

	private static void compareXmlRevocation(XmlRevocation xmlRevocation1, XmlRevocation xmlRevocation2) {
		compareXmlAbstractToken(xmlRevocation1, xmlRevocation2);
		assertEquals(xmlRevocation1.getOrigin(), xmlRevocation2.getOrigin());
		assertEquals(xmlRevocation1.getType(), xmlRevocation2.getType());
		assertEquals(xmlRevocation1.getSourceAddress(), xmlRevocation2.getSourceAddress());
		assertDateEquals(xmlRevocation1.getProductionDate(), xmlRevocation2.getProductionDate());
		assertDateEquals(xmlRevocation1.getThisUpdate(), xmlRevocation2.getThisUpdate());
		assertDateEquals(xmlRevocation1.getNextUpdate(), xmlRevocation2.getNextUpdate());
		assertDateEquals(xmlRevocation1.getExpiredCertsOnCRL(), xmlRevocation2.getExpiredCertsOnCRL());
		assertDateEquals(xmlRevocation1.getArchiveCutOff(), xmlRevocation2.getArchiveCutOff());
		assertEquals(xmlRevocation1.isCertHashExtensionPresent(), xmlRevocation2.isCertHashExtensionPresent());
		assertEquals(xmlRevocation1.isCertHashExtensionMatch(), xmlRevocation2.isCertHashExtensionMatch());
		compareXmlBasicSignature(xmlRevocation1.getBasicSignature(), xmlRevocation2.getBasicSignature());
		compareSigningCertificate(xmlRevocation1.getSigningCertificate(), xmlRevocation2.getSigningCertificate());
		compareCertificateChain(xmlRevocation1.getCertificateChain(), xmlRevocation2.getCertificateChain());
		compareXmlFoundCertificates(xmlRevocation1.getFoundCertificates(), xmlRevocation2.getFoundCertificates());
		assertArrayEquals(xmlRevocation1.getBase64Encoded(), xmlRevocation2.getBase64Encoded());
		compareXmDigestAlgoAndValue(xmlRevocation1.getDigestAlgoAndValue(), xmlRevocation2.getDigestAlgoAndValue());
	}

	private static void compareXmlTimestamps(List<XmlTimestamp> timestamps1, List<XmlTimestamp> timestamps2) {
		assertEquals(Utils.collectionSize(timestamps1), Utils.collectionSize(timestamps2));
		if (Utils.isCollectionNotEmpty(timestamps1)) {
			for (int i = 0; i < timestamps1.size(); i++) {
				compareXmlTimestamp(timestamps1.get(i), timestamps2.get(i));
			}
		}
	}

	private static void compareXmlTimestamp(XmlTimestamp xmlTimestamp1, XmlTimestamp xmlTimestamp2) {
		compareXmlAbstractToken(xmlTimestamp1, xmlTimestamp2);
		assertEquals(xmlTimestamp1.getTimestampFilename(), xmlTimestamp2.getTimestampFilename());
		assertEquals(xmlTimestamp1.getArchiveTimestampType(), xmlTimestamp2.getArchiveTimestampType());
		assertEquals(xmlTimestamp1.getEvidenceRecordTimestampType(), xmlTimestamp2.getEvidenceRecordTimestampType());
		compareXmlArchiveTimestampHashIndex(xmlTimestamp1.getArchiveTimestampHashIndex(), xmlTimestamp2.getArchiveTimestampHashIndex());
		assertDateEquals(xmlTimestamp1.getProductionTime(), xmlTimestamp2.getProductionTime());
		compareXmlDigestMatchers(xmlTimestamp1.getDigestMatchers(), xmlTimestamp2.getDigestMatchers());
		compareXmlBasicSignature(xmlTimestamp1.getBasicSignature(), xmlTimestamp2.getBasicSignature());
		compareSigningCertificate(xmlTimestamp1.getSigningCertificate(), xmlTimestamp2.getSigningCertificate());
		compareCertificateChain(xmlTimestamp1.getCertificateChain(), xmlTimestamp2.getCertificateChain());
		compareXmlSignerInfos(xmlTimestamp1.getSignerInformationStore(), xmlTimestamp2.getSignerInformationStore());
		compareXmlTSAGeneralName(xmlTimestamp1.getTSAGeneralName(), xmlTimestamp2.getTSAGeneralName());
		compareXmlPdfRevision(xmlTimestamp1.getPDFRevision(), xmlTimestamp2.getPDFRevision());
		compareXmlFoundCertificates(xmlTimestamp1.getFoundCertificates(), xmlTimestamp2.getFoundCertificates());
		compareXmlFoundRevocations(xmlTimestamp1.getFoundRevocations(), xmlTimestamp2.getFoundRevocations());
		compareXmlFoundEvidenceRecords(xmlTimestamp1.getFoundEvidenceRecords(), xmlTimestamp2.getFoundEvidenceRecords());
		compareXmlTimestampedObjects(xmlTimestamp1.getTimestampedObjects(), xmlTimestamp2.getTimestampedObjects());
		compareXmlSignatureScopes(xmlTimestamp1.getTimestampScopes(), xmlTimestamp2.getTimestampScopes());
		assertArrayEquals(xmlTimestamp1.getBase64Encoded(), xmlTimestamp2.getBase64Encoded());
		compareXmDigestAlgoAndValue(xmlTimestamp1.getDigestAlgoAndValue(), xmlTimestamp2.getDigestAlgoAndValue());
		assertEquals(xmlTimestamp1.getType(), xmlTimestamp2.getType());
	}

	private static void compareXmlArchiveTimestampHashIndex(XmlArchiveTimestampHashIndex archiveTimestampHashIndex1, XmlArchiveTimestampHashIndex archiveTimestampHashIndex2) {
		assertEquals(archiveTimestampHashIndex1 == null, archiveTimestampHashIndex2 == null);
		if (archiveTimestampHashIndex1 != null) {
			compareXmlStructuralValidation(archiveTimestampHashIndex1, archiveTimestampHashIndex2);
			assertEquals(archiveTimestampHashIndex1.getVersion(), archiveTimestampHashIndex2.getVersion());
		}
	}

	private static void compareXmlTSAGeneralName(XmlTSAGeneralName tsaGeneralName1, XmlTSAGeneralName tsaGeneralName2) {
		assertEquals(tsaGeneralName1 == null, tsaGeneralName2 == null);
		if (tsaGeneralName1 != null) {
			assertEquals(tsaGeneralName1.getValue(), tsaGeneralName2.getValue());
			assertEquals(tsaGeneralName1.isContentMatch(), tsaGeneralName2.isContentMatch());
			assertEquals(tsaGeneralName1.isOrderMatch(), tsaGeneralName2.isOrderMatch());
		}
	}

	private static void compareXmlOrphanTokens(XmlOrphanTokens orphanTokens1, XmlOrphanTokens orphanTokens2) {
		assertEquals(orphanTokens1 == null, orphanTokens2 == null);
		if (orphanTokens1 != null) {
			compareXmlOrphanCertificateTokens(orphanTokens1.getOrphanCertificates(), orphanTokens2.getOrphanCertificates());
			compareXmlOrphanRevocationTokens(orphanTokens1.getOrphanRevocations(), orphanTokens2.getOrphanRevocations());
		}
	}

	private static void compareXmlOrphanCertificateTokens(List<XmlOrphanCertificateToken> orphanCertificates1, List<XmlOrphanCertificateToken> orphanCertificates2) {
		assertEquals(Utils.collectionSize(orphanCertificates1), Utils.collectionSize(orphanCertificates2));
		if (Utils.isCollectionNotEmpty(orphanCertificates1)) {
			for (int i = 0; i < orphanCertificates1.size(); i++) {
				compareXmlOrphanCertificateToken(orphanCertificates1.get(i), orphanCertificates2.get(i));
			}
		}
	}

	private static void compareXmlOrphanCertificateToken(XmlOrphanCertificateToken xmlOrphanCertificateToken1, XmlOrphanCertificateToken xmlOrphanCertificateToken2) {
		compareXmlOrphanToken(xmlOrphanCertificateToken1, xmlOrphanCertificateToken2);
		compareXmlDistinguishedNames(xmlOrphanCertificateToken1.getSubjectDistinguishedName(), xmlOrphanCertificateToken2.getSubjectDistinguishedName());
		compareXmlDistinguishedNames(xmlOrphanCertificateToken1.getIssuerDistinguishedName(), xmlOrphanCertificateToken2.getIssuerDistinguishedName());
		assertEquals(xmlOrphanCertificateToken1.getSerialNumber(), xmlOrphanCertificateToken2.getSerialNumber());
		assertDateEquals(xmlOrphanCertificateToken1.getNotAfter(), xmlOrphanCertificateToken2.getNotAfter());
		assertDateEquals(xmlOrphanCertificateToken1.getNotBefore(), xmlOrphanCertificateToken2.getNotBefore());
		assertEquals(xmlOrphanCertificateToken1.getEntityKey(), xmlOrphanCertificateToken2.getEntityKey());
		assertEquals(xmlOrphanCertificateToken1.isTrusted(), xmlOrphanCertificateToken2.isTrusted());
		assertEquals(xmlOrphanCertificateToken1.isSelfSigned(), xmlOrphanCertificateToken2.isSelfSigned());
		assertArrayEquals(xmlOrphanCertificateToken1.getBase64Encoded(), xmlOrphanCertificateToken2.getBase64Encoded());
		compareXmDigestAlgoAndValue(xmlOrphanCertificateToken1.getDigestAlgoAndValue(), xmlOrphanCertificateToken2.getDigestAlgoAndValue());
	}

	private static void compareXmlOrphanToken(XmlOrphanToken xmlOrphanToken1, XmlOrphanToken xmlOrphanToken2) {
		compareXmlAbstractToken(xmlOrphanToken1, xmlOrphanToken2);
		assertEquals(xmlOrphanToken1.getEncapsulationType(), xmlOrphanToken2.getEncapsulationType());
	}

	private static void compareXmlOrphanRevocationTokens(List<XmlOrphanRevocationToken> orphanRevocations1, List<XmlOrphanRevocationToken> orphanRevocations2) {
		assertEquals(Utils.collectionSize(orphanRevocations1), Utils.collectionSize(orphanRevocations2));
		if (Utils.isCollectionNotEmpty(orphanRevocations1)) {
			for (int i = 0; i < orphanRevocations1.size(); i++) {
				compareXmlOrphanRevocationToken(orphanRevocations1.get(i), orphanRevocations2.get(i));
			}
		}
	}

	private static void compareXmlOrphanRevocationToken(XmlOrphanRevocationToken xmlOrphanRevocationToken1, XmlOrphanRevocationToken xmlOrphanRevocationToken2) {
		compareXmlOrphanToken(xmlOrphanRevocationToken1, xmlOrphanRevocationToken2);
		assertEquals(xmlOrphanRevocationToken1.getRevocationType(), xmlOrphanRevocationToken2.getRevocationType());
		assertArrayEquals(xmlOrphanRevocationToken1.getBase64Encoded(), xmlOrphanRevocationToken2.getBase64Encoded());
		compareXmDigestAlgoAndValue(xmlOrphanRevocationToken1.getDigestAlgoAndValue(), xmlOrphanRevocationToken2.getDigestAlgoAndValue());
	}

	private static void compareXmlSignerDatas(List<XmlSignerData> signerData1, List<XmlSignerData> signerData2) {
		assertEquals(Utils.collectionSize(signerData1), Utils.collectionSize(signerData2));
		if (Utils.isCollectionNotEmpty(signerData1)) {
			for (int i = 0; i < signerData1.size(); i++) {
				compareXmlSignerData(signerData1.get(i), signerData2.get(i));
			}
		}
	}

	private static void compareXmlSignerData(XmlSignerData xmlSignerData1, XmlSignerData xmlSignerData2) {
		compareXmlAbstractToken(xmlSignerData1, xmlSignerData2);
		assertEquals(xmlSignerData1.getReferencedName(), xmlSignerData2.getReferencedName());
		compareXmDigestAlgoAndValue(xmlSignerData1.getDigestAlgoAndValue(), xmlSignerData2.getDigestAlgoAndValue());
		compareXmlTokenIDREF(xmlSignerData1.getParent(), xmlSignerData2.getParent());
	}

	private static void compareXmlTrustedLists(List<XmlTrustedList> trustedLists1, List<XmlTrustedList> trustedLists2) {
		assertEquals(Utils.collectionSize(trustedLists1), Utils.collectionSize(trustedLists2));
		if (Utils.isCollectionNotEmpty(trustedLists1)) {
			for (int i = 0; i < trustedLists1.size(); i++) {
				compareXmlTrustedList(trustedLists1.get(i), trustedLists2.get(i));
			}
		}
	}

	private static void compareXmlTrustedList(XmlTrustedList xmlTrustedList1, XmlTrustedList xmlTrustedList2) {
		assertEquals(xmlTrustedList1.getCountryCode(), xmlTrustedList2.getCountryCode());
		assertEquals(xmlTrustedList1.getUrl(), xmlTrustedList2.getUrl());
		assertEquals(xmlTrustedList1.getTSLType(), xmlTrustedList2.getTSLType());
		assertEquals(xmlTrustedList1.getSequenceNumber(), xmlTrustedList2.getSequenceNumber());
		assertEquals(xmlTrustedList1.getVersion(), xmlTrustedList2.getVersion());
		assertDateEquals(xmlTrustedList1.getLastLoading(), xmlTrustedList2.getLastLoading());
		assertDateEquals(xmlTrustedList1.getIssueDate(), xmlTrustedList2.getIssueDate());
		assertDateEquals(xmlTrustedList1.getNextUpdate(), xmlTrustedList2.getNextUpdate());
		assertEquals(xmlTrustedList1.isWellSigned(), xmlTrustedList2.isWellSigned());
		compareXmlStructuralValidation(xmlTrustedList1.getStructuralValidation(), xmlTrustedList2.getStructuralValidation());
		assertEquals(xmlTrustedList1.getId(), xmlTrustedList2.getId());
		assertEquals(xmlTrustedList1.isLOTL(), xmlTrustedList2.isLOTL());
		compareXmlTLIDREF(xmlTrustedList1.getParent(), xmlTrustedList2.getParent());
		assertEquals(xmlTrustedList1.isMra(), xmlTrustedList2.isMra());
	}

	private static void assertDateEquals(Date date1, Date date2) {
		assertEquals(date1 == null, date2 == null);
		if (date1 != null) {
			assertEquals(0, truncateMillis(date1).compareTo(truncateMillis(date2)));
		}
	}

	private static Date truncateMillis(Date date) {
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(date);
		calendar.set(Calendar.MILLISECOND, 0);
		return calendar.getTime();
	}

}
