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
package eu.europa.esig.dss.validation.executor;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicValidation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVTS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalDataTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationTimestampQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationTimestampQualificationAtTime;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlByteRange;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateExtension;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicies;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDistinguishedName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDocMDP;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificates;
import eu.europa.esig.dss.diagnostic.jaxb.XmlIdPkixOcspNoCheck;
import eu.europa.esig.dss.diagnostic.jaxb.XmlKeyUsages;
import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModifications;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFAInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFLockDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPSD2QcInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcCompliance;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcEuLimitValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcSSCD;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRoleOfPSP;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureDigestReference;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStructuralValidation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSubjectAlternativeNames;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTSAGeneralName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustService;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustServiceProvider;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.CertificatePolicy;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.MRAEquivalenceContext;
import eu.europa.esig.dss.enumerations.PdfLockAction;
import eu.europa.esig.dss.enumerations.PdfObjectModificationType;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.ContainerConstraints;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.IntValueConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.Model;
import eu.europa.esig.dss.policy.jaxb.ModelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.RevocationConstraints;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.SignedAttributesConstraints;
import eu.europa.esig.dss.policy.jaxb.TimeConstraint;
import eu.europa.esig.dss.policy.jaxb.TimeUnit;
import eu.europa.esig.dss.policy.jaxb.TimestampConstraints;
import eu.europa.esig.dss.policy.jaxb.ValueConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.enums.TypeOfProof;
import eu.europa.esig.validationreport.jaxb.POEProvisioningType;
import eu.europa.esig.validationreport.jaxb.POEType;
import eu.europa.esig.validationreport.jaxb.SignatureReferenceType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.VOReferenceType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationTimeInfoType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import jakarta.xml.bind.JAXB;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CustomProcessExecutorTest extends AbstractTestValidationExecutor {
	
	private static I18nProvider i18nProvider;
	
	@BeforeAll
	public static void init() {
		i18nProvider = new I18nProvider(Locale.getDefault());
	}

	@Test
	public void skipRevocationDataValidation() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/it.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicyNoRevoc());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// TODO: Etsi Validation Report

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void outOfBoundNotRevoked() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/out-of-bound-not-revoked.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setIncludeSemantics(true);

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		assertNull(simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));
		assertNull(simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
		assertNotNull(validationProcessBasicSignature.getTitle());
		assertNotNull(validationProcessBasicSignature.getProofOfExistence());

		boolean x509CVCheckFound = false;
		boolean x509OutOfBoundsCheckFound = false;
		boolean basicSignatureValidationCheckFound = false;
		for (XmlConstraint constraint : validationProcessBasicSignature.getConstraint()) {
			if (MessageTag.BSV_IXCVRC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				x509CVCheckFound = true;
			} else if (MessageTag.BSV_IVTAVRSC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				x509OutOfBoundsCheckFound = true;
			} else if (MessageTag.ADEST_ROBVPIIC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				basicSignatureValidationCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(x509CVCheckFound);
		assertTrue(x509OutOfBoundsCheckFound);
		assertTrue(basicSignatureValidationCheckFound);

		assertFalse(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getWarnings()),
				i18nProvider.getMessage(MessageTag.BSV_IXCVRC_ANS)));
		assertFalse(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getWarnings()),
				i18nProvider.getMessage(MessageTag.BSV_IVTAVRSC_ANS)));
		assertFalse(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.ADEST_ROBVPIIC_ANS)));

		assertEquals(0, detailedReport.getTimestampIds().size());

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}
	
	@Test
	public void test() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/algo.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// TODO: Etsi Validation Report

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		assertNull(simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));
		assertNotNull(simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));


		validateBestSigningTimes(reports);
		checkReports(reports);
	}
	
	@Test
	public void test2() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/algo2.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// TODO: Etsi Validation Report

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}
	
	@Test
	public void testDSS1344() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/dss-1344.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testDSS1344CryptoWarn() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/dss-1344.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicyCryptoWarn());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		assertNotNull(simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));
		assertNotNull(simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testDSS1686() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-1686/dss-1686.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
//		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.INDETERMINATE_QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationReport);
		assertEquals(simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()), 
				SignatureQualification.forURI(signatureValidationReport.getSignatureQuality().getSignatureQualityInformation().get(0)));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getSignatures().get(0);

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(xmlSignature.getId());

		XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
		XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();

		assertEquals(signatureBBB.getConclusion().getIndication(),
				validationProcessArchivalData.getConclusion().getIndication());
		assertEquals(signatureBBB.getConclusion().getSubIndication(),
				validationProcessArchivalData.getConclusion().getSubIndication());
		assertTrue(signatureBBB.getConclusion().getErrors().containsAll(
				validationProcessBasicSignature.getConclusion().getErrors()));
		assertTrue(signatureBBB.getConclusion().getWarnings().containsAll(
				validationProcessBasicSignature.getConclusion().getWarnings()));

		assertNotNull(signatureBBB.getPSV());
		assertTrue(signatureBBB.getConclusion().getErrors().containsAll(
				signatureBBB.getPSV().getConclusion().getErrors()));
		assertTrue(signatureBBB.getConclusion().getWarnings().containsAll(
				signatureBBB.getPSV().getConclusion().getWarnings()));

		List<XmlConstraint> constraints = validationProcessArchivalData.getConstraint();
		List<String> timestampIds = detailedReport.getTimestampIds();
		
		int validationTSTCounter = 0;
		for (String timestampId : timestampIds) {
			for (XmlConstraint constraint : constraints) {
				if (Utils.isStringNotEmpty(constraint.getId()) && constraint.getId().contains(timestampId)) {
					if (MessageTag.ADEST_IBSVPTADC.getId().equals(constraint.getName().getKey())) {
						assertEquals(XmlStatus.OK, constraint.getStatus());
						++validationTSTCounter;
					}
				}
			}
			assertEquals(Indication.PASSED, detailedReport.getBasicBuildingBlocksIndication(timestampId));
			assertNull(detailedReport.getBasicBuildingBlocksSubIndication(timestampId));
		}
		assertEquals(3, validationTSTCounter);

		assertEquals(3, xmlSignature.getTimestamps().size());

		int basicTstSuccessCounter = 0;
		int basicTstFailureCounter = 0;
		for (eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp : xmlSignature.getTimestamps()) {
			boolean passedTst = false;
			XmlValidationProcessBasicTimestamp timestampBasicValidation = xmlTimestamp.getValidationProcessBasicTimestamp();
			if (Indication.PASSED.equals(timestampBasicValidation.getConclusion().getIndication())) {
				passedTst = true;
				++basicTstSuccessCounter;
			} else {
				assertEquals(Indication.INDETERMINATE, timestampBasicValidation.getConclusion().getIndication());
				assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, timestampBasicValidation.getConclusion().getSubIndication());
				++basicTstFailureCounter;
			}

			boolean basicTstAcceptableCheckFound = false;
			boolean basicTstConclusiveCheckFound = false;
			boolean pastTstAcceptableCheckFound = false;
			boolean digestAlgoTstCheckFound = false;
			boolean messageImprintTstCheckFound = false;

			XmlValidationProcessArchivalDataTimestamp timestampArchivalDataValidation = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
			assertEquals(Indication.PASSED, timestampArchivalDataValidation.getConclusion().getIndication());
			for (XmlConstraint constraint : timestampArchivalDataValidation.getConstraint()) {
				if (MessageTag.ARCH_IRTVBBA.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					basicTstAcceptableCheckFound = true;

				} else if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
					if (passedTst) {
						assertEquals(XmlStatus.OK, constraint.getStatus());
					} else {
						assertEquals(XmlStatus.WARNING, constraint.getStatus());
						assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
					}
					basicTstConclusiveCheckFound = true;

				} else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					pastTstAcceptableCheckFound = true;

				} else if (MessageTag.ARCH_ICHFCRLPOET.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					digestAlgoTstCheckFound = true;

				} else if (MessageTag.BBB_SAV_DMICTSTMCMI.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					messageImprintTstCheckFound = true;

				} else {
					assertEquals(XmlStatus.OK, constraint.getStatus());
				}
			}

			assertTrue(basicTstAcceptableCheckFound);
			assertTrue(basicTstConclusiveCheckFound);
			if (!passedTst) {
				assertTrue(pastTstAcceptableCheckFound);
			}
			assertTrue(digestAlgoTstCheckFound);
			assertTrue(messageImprintTstCheckFound);
		}
		assertEquals(1, basicTstSuccessCounter);
		assertEquals(2, basicTstFailureCounter);

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testDSS1686CheckManifestEntryExistence() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-1686/dss-1686.xml"));
		assertNotNull(diagnosticData);
		
		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
		BasicSignatureConstraints basicSignatureConstraints = signatureConstraints.getBasicSignatureConstraints();
		
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.INDETERMINATE_ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_CV_ISMEC_ANS)));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}
	
	@Test
	public void testDSS1686CryptoWarn() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-1686/dss-1686.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicyCryptoWarn());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationReport);
		assertEquals(simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()), 
				SignatureQualification.forURI(signatureValidationReport.getSignatureQuality().getSignatureQualityInformation().get(0)));
		
		Date timestampProductionDate = diagnosticData.getSignatures().get(0).getFoundTimestamps().get(0).getTimestamp().getProductionTime();
		Date bestSignatureTime = simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId());
		assertEquals(timestampProductionDate, bestSignatureTime);
		
		assertEquals(0, simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()).size());
		assertEquals(4, simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()).size());

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testDSS1686BrokenSigTimestamp() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/DSS-1686/dss-1686-broken-signature-timestamp.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		// Sig TST is broken -> best signing time is not updated
		assertEquals(SignatureQualification.INDETERMINATE_QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getSignatures().get(0);
		XmlValidationProcessBasicTimestamp validationProcessTimestamp = xmlSignature.getTimestamps().get(0).getValidationProcessBasicTimestamp();
		assertEquals(Indication.FAILED, validationProcessTimestamp.getConclusion().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, validationProcessTimestamp.getConclusion().getSubIndication());

		XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
		boolean sigTstMessageImprintCheckFound = false;
		for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
			if (MessageTag.BBB_SAV_DMICTSTMCMI.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.BBB_SAV_DMICTSTMCMI_ANS.getId(), constraint.getWarning().getKey());
				sigTstMessageImprintCheckFound = true;
			}
		}
		assertTrue(sigTstMessageImprintCheckFound);

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testDSS1686BrokenSigTimestampSkipDigestMatcherCheck() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/DSS-1686/dss-1686-broken-signature-timestamp.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		BasicSignatureConstraints timestampBasicSignatureConstraints = validationPolicy.getTimestampConstraints()
				.getBasicSignatureConstraints();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);

		timestampBasicSignatureConstraints.setReferenceDataExistence(levelConstraint);
		timestampBasicSignatureConstraints.setReferenceDataIntact(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.INDETERMINATE_QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getSignatures().get(0);
		XmlValidationProcessBasicTimestamp validationProcessTimestamp = xmlSignature.getTimestamps().get(0).getValidationProcessBasicTimestamp();
		assertEquals(Indication.INDETERMINATE, validationProcessTimestamp.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessTimestamp.getConclusion().getSubIndication());

		XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
		boolean sigTstMessageImprintCheckFound = false;
		for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
			if (MessageTag.BBB_SAV_DMICTSTMCMI.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.BBB_SAV_DMICTSTMCMI_ANS.getId(), constraint.getWarning().getKey());
				sigTstMessageImprintCheckFound = true;
			}
		}
		assertTrue(sigTstMessageImprintCheckFound);

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testDSS1686BrokenSigTimestampCryptoWarn() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/DSS-1686/dss-1686-broken-signature-timestamp.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicyCryptoWarn());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks basicBuildingBlockSigTimestamp = detailedReport
				.getBasicBuildingBlockById("T-BFE8B3E24DC946E83C989B65401FE6B41A8EC7A3C047F7579E01F5EA39D718B1");
		assertNotNull(basicBuildingBlockSigTimestamp);
		assertEquals(Indication.FAILED, basicBuildingBlockSigTimestamp.getConclusion().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, basicBuildingBlockSigTimestamp.getConclusion().getSubIndication());

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		// Sig TST is broken -> best signing time is not updated
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testDSS1686BrokenSigAndArchivalTimestamp() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/DSS-1686/dss-1686-broken-signature-and-archival-timestamp.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		// Sig TST + archival TST are broken -> unable to process the past signature
		// validation + POE extraction
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.INDETERMINATE_ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getSignatures().get(0);

		int validationTSTPassedCounter = 0;
		int validationTSTFailedCounter = 0;
		XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
		List<XmlConstraint> constraints = validationProcessArchivalData.getConstraint();
		List<String> timestampIds = detailedReport.getTimestampIds();
		for (String timestampId : timestampIds) {
			for (XmlConstraint constraint : constraints) {
				if (timestampId.equals(constraint.getId())) {
					if (MessageTag.ADEST_IBSVPTADC.getId().equals(constraint.getName().getKey())) {
						if (XmlStatus.OK.equals(constraint.getStatus())) {
							assertEquals(Indication.PASSED, detailedReport.getBasicBuildingBlocksIndication(timestampId));
							++validationTSTPassedCounter;
						} else if (XmlStatus.WARNING.equals(constraint.getStatus())) {
							assertEquals(Indication.FAILED, detailedReport.getBasicBuildingBlocksIndication(timestampId));
							assertEquals(SubIndication.HASH_FAILURE, detailedReport.getBasicBuildingBlocksSubIndication(timestampId));
							++validationTSTFailedCounter;
						}
					}
				}
			}
		}
		assertEquals(1, validationTSTPassedCounter);
		assertEquals(2, validationTSTFailedCounter);

		int basicTstSuccessCounter = 0;
		int basicTstFailureCounter = 0;

		for (eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp : xmlSignature.getTimestamps()) {
			boolean passedTst = false;
			XmlValidationProcessBasicTimestamp timestampBasicValidation = xmlTimestamp.getValidationProcessBasicTimestamp();
			if (Indication.PASSED.equals(timestampBasicValidation.getConclusion().getIndication())) {
				passedTst = true;
				++basicTstSuccessCounter;
			} else {
				++basicTstFailureCounter;
			}

			boolean basicTstAcceptableCheckFound = false;
			boolean basicTstConclusiveCheckFound = false;
			boolean pastTstAcceptableCheckFound = false;
			boolean digestAlgoTstCheckFound = false;
			boolean messageImprintTstCheckFound = false;

			XmlValidationProcessArchivalDataTimestamp timestampArchivalDataValidation = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
			for (XmlConstraint constraint : timestampArchivalDataValidation.getConstraint()) {
				if (MessageTag.ARCH_IRTVBBA.getId().equals(constraint.getName().getKey())) {
					if (XmlStatus.OK.equals(constraint.getStatus())) {
						assertTrue(passedTst);
						assertEquals(Indication.PASSED, timestampArchivalDataValidation.getConclusion().getIndication());
					} else {
						assertEquals(Indication.FAILED, timestampArchivalDataValidation.getConclusion().getIndication());
						assertEquals(SubIndication.HASH_FAILURE, timestampArchivalDataValidation.getConclusion().getSubIndication());
					}
					basicTstAcceptableCheckFound = true;

				} else if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
					assertTrue(passedTst);
					assertEquals(XmlStatus.OK, constraint.getStatus());
					basicTstConclusiveCheckFound = true;

				} else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
					assertTrue(passedTst);
					assertEquals(XmlStatus.OK, constraint.getStatus());
					pastTstAcceptableCheckFound = true;

				} else if (MessageTag.ARCH_ICHFCRLPOET.getId().equals(constraint.getName().getKey())) {
					assertTrue(passedTst);
					assertEquals(XmlStatus.OK, constraint.getStatus());
					digestAlgoTstCheckFound = true;

				} else if (MessageTag.BBB_SAV_DMICTSTMCMI.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					assertTrue(passedTst);
					messageImprintTstCheckFound = true;

				} else {
					assertEquals(XmlStatus.OK, constraint.getStatus());
				}
			}

			assertTrue(basicTstAcceptableCheckFound);
			if (passedTst) {
				assertTrue(basicTstConclusiveCheckFound);
				assertTrue(digestAlgoTstCheckFound);
				assertTrue(messageImprintTstCheckFound);
			}
		}

		assertEquals(1, basicTstSuccessCounter);
		assertEquals(2, basicTstFailureCounter);

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testDSS1686BrokenSigAndArchivalTimestampSkipDigestMatcherCheck() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/DSS-1686/dss-1686-broken-signature-and-archival-timestamp.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		BasicSignatureConstraints timestampBasicConstraints = validationPolicy.getTimestampConstraints().getBasicSignatureConstraints();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);

		timestampBasicConstraints.setReferenceDataExistence(levelConstraint);
		timestampBasicConstraints.setReferenceDataIntact(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		// Sig TST + archival TST are broken -> unable to process the past signature
		// validation + POE extraction
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.INDETERMINATE_ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		int tstPassedCounter = 0;

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getSignatures().get(0);
		XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
		List<XmlConstraint> constraints = validationProcessArchivalData.getConstraint();
		List<String> timestampIds = detailedReport.getTimestampIds();
		for (String timestampId : timestampIds) {
			for (XmlConstraint constraint : constraints) {
				if (timestampId.equals(constraint.getId())) {
					if (MessageTag.ADEST_IBSVPTADC.getId().equals(constraint.getName().getKey())) {
						if (XmlStatus.OK.equals(constraint.getStatus())) {
							++tstPassedCounter;
						}
					}
				}
			}
			assertEquals(Indication.PASSED, detailedReport.getBasicBuildingBlocksIndication(timestampId));
		}
		assertEquals(3, tstPassedCounter);

		int basicTstSuccessCounter = 0;
		int basicTstFailureCounter = 0;

		int messageImprintCheckPassedCounter = 0;
		int messageImprintCheckFailedCounter = 0;

		for (eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp : xmlSignature.getTimestamps()) {
			boolean passedTst = false;
			XmlValidationProcessBasicTimestamp timestampBasicValidation = xmlTimestamp.getValidationProcessBasicTimestamp();
			if (Indication.PASSED.equals(timestampBasicValidation.getConclusion().getIndication())) {
				passedTst = true;
				++basicTstSuccessCounter;
			} else {
				assertEquals(Indication.INDETERMINATE, timestampBasicValidation.getConclusion().getIndication());
				assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, timestampBasicValidation.getConclusion().getSubIndication());
				++basicTstFailureCounter;
			}

			boolean basicTstAcceptableCheckFound = false;
			boolean basicTstConclusiveCheckFound = false;
			boolean pastTstAcceptableCheckFound = false;
			boolean digestAlgoTstCheckFound = false;
			boolean messageImprintTstCheckFound = false;

			XmlValidationProcessArchivalDataTimestamp timestampArchivalDataValidation = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
			assertEquals(Indication.PASSED, timestampArchivalDataValidation.getConclusion().getIndication());
			for (XmlConstraint constraint : timestampArchivalDataValidation.getConstraint()) {
				if (MessageTag.ARCH_IRTVBBA.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					basicTstAcceptableCheckFound = true;

				} else if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
					if (passedTst) {
						assertEquals(XmlStatus.OK, constraint.getStatus());
					} else {
						assertEquals(XmlStatus.WARNING, constraint.getStatus());
						assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
					}
					basicTstConclusiveCheckFound = true;

				} else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					pastTstAcceptableCheckFound = true;

				} else if (MessageTag.ARCH_ICHFCRLPOET.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					digestAlgoTstCheckFound = true;

				} else if (MessageTag.BBB_SAV_DMICTSTMCMI.getId().equals(constraint.getName().getKey())) {
					if (XmlStatus.OK.equals(constraint.getStatus())) {
						++messageImprintCheckPassedCounter;
					} else {
						++messageImprintCheckFailedCounter;
					}
					messageImprintTstCheckFound = true;

				} else {
					assertEquals(XmlStatus.OK, constraint.getStatus());
				}
			}

			assertTrue(basicTstAcceptableCheckFound);
			assertTrue(basicTstConclusiveCheckFound);
			if (!passedTst) {
				assertTrue(pastTstAcceptableCheckFound);
			}
			assertTrue(digestAlgoTstCheckFound);
			assertTrue(messageImprintTstCheckFound);
		}

		assertEquals(1, basicTstSuccessCounter);
		assertEquals(2, basicTstFailureCounter);
		assertEquals(1, messageImprintCheckPassedCounter);
		assertEquals(2, messageImprintCheckFailedCounter);

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testDSS1686noSignedDataFound() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/DSS-1686/dss-1686-signedData-notFound.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.INDETERMINATE_ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		
		Date timestampProductionDate = diagnosticData.getSignatures().get(0).getFoundTimestamps().get(0).getTimestamp().getProductionTime();
		Date bestSignatureTime = simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId());
		assertNotEquals(timestampProductionDate, bestSignatureTime);
		assertEquals(diagnosticData.getValidationDate(), bestSignatureTime);

		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertEquals(4, errors.size());

		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_SIG_SIG)));
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_REVOC_SIG)));
		assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_CV_IRDOF_ANS)));
		assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_XCV_SUB_ANS)));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testDSS1686noPOE() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/DSS-1686/dss-1686-noPOE.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.INDETERMINATE_ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		
		Date validationDate = diagnosticData.getValidationDate();
		Date bestSignatureTime = simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId());
		assertEquals(validationDate, bestSignatureTime);

		assertEquals(4, simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()).size());
		assertEquals(3, simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0)
				.getAdESValidationDetails().getError().size());

		DetailedReport detailedReport = reports.getDetailedReport();

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getSignatures().get(0);
		XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
		assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, validationProcessArchivalData.getConclusion().getSubIndication());

		int tstCheckCounter = 0;
		for (XmlConstraint constraint : validationProcessArchivalData.getConstraint()) {
			if (MessageTag.ADEST_IBSVPTADC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), constraint.getWarning().getKey());
				++tstCheckCounter;
			}
		}
		assertEquals(1, tstCheckCounter);

		boolean basicValidationCheckFound = false;
		boolean pastValidationTSTFailedCounter = false;

		XmlValidationProcessArchivalDataTimestamp tstValidationProcessArchivalData = xmlSignature.getTimestamps().get(0).getValidationProcessArchivalDataTimestamp();
		assertEquals(Indication.INDETERMINATE, tstValidationProcessArchivalData.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, tstValidationProcessArchivalData.getConclusion().getSubIndication());

		List<XmlConstraint> constraints = tstValidationProcessArchivalData.getConstraint();
		for (XmlConstraint constraint : constraints) {
			if (MessageTag.ARCH_IRTVBBA.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			} else if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
				basicValidationCheckFound = true;
			} else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.PSV_IPTVC_ANS.getId(), constraint.getError().getKey());
				pastValidationTSTFailedCounter = true;
			}
		}

		assertTrue(basicValidationCheckFound);
		assertTrue(pastValidationTSTFailedCounter);

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testAllFilesCovered() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/all-files-present.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		List<Message> warnings = simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId());
		assertFalse(checkMessageValuePresence(warnings, i18nProvider.getMessage(MessageTag.BBB_CV_IAFS_ANS)));
		assertTrue(checkMessageValuePresence(warnings, i18nProvider.getMessage(MessageTag.BBB_ICS_AIDNASNE_ANS)));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}
	
	@Test
	public void testNotAllFilesCovered() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/all-files-present.xml"));
		assertNotNull(diagnosticData);
		
		XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
		containerInfo.getContentFiles().add("bye.world");
		
		ValidationPolicy validationPolicy = loadDefaultPolicy();
		ContainerConstraints containerConstraints = validationPolicy.getContainerConstraints();
		
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		containerConstraints.setAllFilesSigned(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
		assertNotNull(validationProcessBasicSignature.getTitle());
		assertNotNull(validationProcessBasicSignature.getProofOfExistence());

		boolean fcCheckFound = false;
		for (XmlConstraint constraint : validationProcessBasicSignature.getConstraint()) {
			if (MessageTag.BSV_IFCRC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				fcCheckFound = true;
			}
		}
		assertTrue(fcCheckFound);

		assertFalse(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.BSV_IFCRC_ANS)));

		XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
		assertEquals(validationProcessBasicSignature.getConclusion().getErrors(), validationProcessLongTermData.getConclusion().getErrors());
		assertEquals(validationProcessBasicSignature.getConclusion().getWarnings(), validationProcessLongTermData.getConclusion().getWarnings());
		assertEquals(validationProcessBasicSignature.getConclusion().getInfos(), validationProcessLongTermData.getConclusion().getInfos());

		XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
		assertEquals(validationProcessBasicSignature.getConclusion().getErrors(), validationProcessArchivalData.getConclusion().getErrors());
		assertEquals(validationProcessBasicSignature.getConclusion().getWarnings(), validationProcessArchivalData.getConclusion().getWarnings());
		assertEquals(validationProcessBasicSignature.getConclusion().getInfos(), validationProcessArchivalData.getConclusion().getInfos());

		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_CV_IAFS_ANS)));
		assertFalse(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.LTV_ABSV_ANS)));
		assertFalse(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.ARCH_LTVV_ANS)));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testDSS1453() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-1453/diag-data-lta-dss.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		checkReports(reports);
	}

	// Added LuxTrust Global Root 2
	@Test
	public void testDSS1453Fixed() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-1453/diag-data-lta-dss-fixed.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlXCV xcv = signatureBBB.getXCV();

		// DSS-2385 test
		boolean nestedRACFound = false;
		for (XmlSubXCV subXCV : xcv.getSubXCV()) {
			if (subXCV.getCRS() != null) {
				for (XmlRAC rac : subXCV.getCRS().getRAC()) {
					if (rac.getCRS() != null) {
						for (XmlConstraint constraint : rac.getCRS().getConstraint()) {
							if (XmlBlockType.RAC.equals(constraint.getBlockType())) {
								assertNotNull(constraint.getId());
								XmlBasicBuildingBlocks revBBB = detailedReport.getBasicBuildingBlockById(constraint.getId());
								assertNotNull(revBBB);
								nestedRACFound = true;
							}
						}
					}
				}
			}
		}
		assertTrue(nestedRACFound);
		
		checkReports(reports);
	}

	@Test
	public void testArchiveCutOff() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/archiveCutOff.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
		assertEquals(2, usedTimestamps.size());
		for (XmlTimestamp xmlTimestamp : usedTimestamps) {
			assertEquals(TimestampQualification.QTSA, detailedReport.getTimestampQualification(xmlTimestamp.getId()));
		}

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void signedDataNotFound() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/signed_data_not_found.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(0, detailedReport.getTimestampIds().size());

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void universign() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/universign.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void expiredRevocAndNoCheck() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/expiredRevocAndNoCheck.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void expiredRevocAndNoCheckWithCRL() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/expiredOcspWithNoCheckAndCRL.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();
		assertNotNull(reports);

		// Expiration of the OCSP Responder should not change the validation result
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void expiredRevocAndNoCheckWithCRLWarn() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/expiredOcspWithNoCheckAndCRL.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicyCryptoWarn());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();
		assertNotNull(reports);

		// Expiration of the OCSP Responder should not change the validation result
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void expiredRevocAndNoCheckWithCRLAcceptRevocationSha1() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/expiredOcspWithNoCheckAndCRL.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicyRevocSha1OK());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		// Expiration of the OCSP Responder should not change the validation result
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		
		// cert is not TSA/QTST
		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> timestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		assertEquals(2, timestamps.size());
		for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp : timestamps) {
			assertEquals(1, timestamp.getQualificationDetails().getError().size());
			assertTrue(checkMessageValuePresence(convertMessages(timestamp.getQualificationDetails().getError()),
					i18nProvider.getMessage(MessageTag.QUAL_HAS_QTST_ANS)));
		}

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void noPoeRevokedNoTimestamp() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/no_poe_revoked_no_timestamp.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(0, detailedReport.getTimestampIds().size());

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}
	
	@Test
	public void revokedValidationInPast() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/no_poe_revoked_no_timestamp.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate().getNotBefore());
		
		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void passedRevokedWithTimestamp() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/passed_revoked_with_timestamp.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		List<String> timestampIds = detailedReport.getTimestampIds();
		assertEquals(1, timestampIds.size());

		assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(timestampIds.get(0)));

		assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void passedOutOfBoundsWithTimestamps() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/passed_out_of_bounds_with_timestamps.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

//		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		List<String> timestampIds = detailedReport.getTimestampIds();
		assertEquals(5, timestampIds.size());
		for (String tspId : timestampIds) {
			assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(tspId));
		}

		assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		ValidationObjectListType signatureValidationObjects = etsiValidationReport.getSignatureValidationObjects();
		assertNotNull(signatureValidationObjects);
		assertTrue(Utils.isCollectionNotEmpty(signatureValidationObjects.getValidationObject()));
		
		TimestampWrapper firstArchiveTst = null;
		for (TimestampWrapper timestampWrapper : reports.getDiagnosticData().getTimestampList()) {
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				if (firstArchiveTst == null) {
					firstArchiveTst = timestampWrapper;
				} else if (timestampWrapper.getProductionTime().before(firstArchiveTst.getProductionTime())) {
					firstArchiveTst = timestampWrapper;
				} else if (timestampWrapper.getProductionTime().compareTo(firstArchiveTst.getProductionTime()) == 0 &&
						timestampWrapper.getTimestampedObjects().size() < firstArchiveTst.getTimestampedObjects().size()) {
					firstArchiveTst = timestampWrapper;
				}
			}
		}
		assertNotNull(firstArchiveTst);
		
		List<String> timestampedRevocationIds = firstArchiveTst.getTimestampedRevocations().stream().map(RevocationWrapper::getId)
				.collect(Collectors.toList());
		
		int timestampedRevocationsCounter = 0;
		for (ValidationObjectType validationObject : signatureValidationObjects.getValidationObject()) {
			if (ObjectType.CRL.equals(validationObject.getObjectType())) {
				assertNotNull(validationObject.getId());
				POEType poe = validationObject.getPOE();
				assertNotNull(poe);
				assertNotNull(poe.getPOETime());
				assertNotNull(poe.getTypeOfProof());
				if (timestampedRevocationIds.contains(validationObject.getId())) {
					assertNotNull(poe.getPOEObject());
					assertEquals(1, poe.getPOEObject().getVOReference().size());
					Object poeObject = poe.getPOEObject().getVOReference().get(0);
					assertTrue(poeObject instanceof ValidationObjectType);
					assertEquals(firstArchiveTst.getId(), ((ValidationObjectType) poeObject).getId());
					assertEquals(firstArchiveTst.getProductionTime(), poe.getPOETime());
					++timestampedRevocationsCounter;
				}
			}
		}
		assertEquals(2, timestampedRevocationsCounter);

		validateBestSigningTimes(reports);
		checkReports(reports);
	}
	
	@Test
	public void revokedWithNotTrustedOCSP() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/revoked_ocsp_not_trusted.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);
		
		XmlXCV xcv = signatureBBB.getXCV();
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());
		
		XmlSubXCV xmlSubXCV = xcv.getSubXCV().get(0);
		assertNotNull(xmlSubXCV);
		List<XmlRAC> xmlRACs = xmlSubXCV.getCRS().getRAC();
		assertEquals(1, xmlRACs.size());
		XmlRAC xmlRAC = xmlRACs.get(0);
		assertEquals(Indication.INDETERMINATE, xmlRAC.getConclusion().getIndication());
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, xmlRAC.getConclusion().getSubIndication());

		XmlCRS crs = xmlSubXCV.getCRS();
		assertNotNull(crs);
		assertTrue(checkMessageValuePresence(convert(crs.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));
		List<XmlConstraint> crsConstraints = crs.getConstraint();
		XmlConstraint constraint = crsConstraints.get(crsConstraints.size() - 1);
		assertEquals(MessageTag.BBB_XCV_IARDPFC.name(), constraint.getName().getKey());
		assertEquals(i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS), constraint.getError().getValue());
		assertEquals(Indication.INDETERMINATE, crs.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, crs.getConclusion().getSubIndication());
	}
	
	@Test
	public void revokedCATest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/ca-revoked.xml"));
		assertNotNull(xmlDiagnosticData);
		
		ConstraintsParameters constraintsParameters = getConstraintsParameters(new File("src/test/resources/policy/default-only-constraint-policy.xml"));
		ModelConstraint modelConstraint = new ModelConstraint();
		modelConstraint.setValue(Model.SHELL);
		constraintsParameters.setModel(modelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(new EtsiValidationPolicy(constraintsParameters));
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_CA_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_CA_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));
		
		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_CA_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));
		
		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_CA_NO_POE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));
		
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		CertificateWrapper signingCertificate = signatureWrapper.getSigningCertificate();
		assertNotNull(signingCertificate);
		
		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		XmlSubXCV xmlSubXCV = subXCVs.get(0);
		assertEquals(signingCertificate.getId(), xmlSubXCV.getId());
		assertEquals(Indication.PASSED, xmlSubXCV.getConclusion().getIndication());
		
		xmlSubXCV = subXCVs.get(1);
		assertEquals(signingCertificate.getSigningCertificate().getId(), xmlSubXCV.getId());
		assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
		assertEquals(SubIndication.REVOKED_CA_NO_POE, xmlSubXCV.getConclusion().getSubIndication());

		XmlPCV pcv = signatureBBB.getPCV();
		assertNotNull(pcv);

		assertEquals(Indication.INDETERMINATE, pcv.getConclusion().getIndication());
		assertEquals(SubIndication.NO_POE, pcv.getConclusion().getSubIndication());

		XmlVTS vts = signatureBBB.getVTS();

		assertEquals(Indication.INDETERMINATE, vts.getConclusion().getIndication());
		assertEquals(SubIndication.NO_POE, vts.getConclusion().getSubIndication());

		List<XmlCRS> crss = vts.getCRS();
		assertEquals(2, crss.size());

		for (XmlCRS xmlCRS : crss) {
			assertEquals(Indication.INDETERMINATE, xmlCRS.getConclusion().getIndication());
			assertEquals(SubIndication.NO_POE, xmlCRS.getConclusion().getSubIndication());

			boolean revocationDataIssuedBeforeControlTimeCheckFound = false;
			for (XmlConstraint constraint : xmlCRS.getConstraint()) {
				if (MessageTag.PSV_HRDBIBCT.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.WARNING, constraint.getStatus());
					assertEquals(MessageTag.PSV_HRDBIBCT_ANS.getId(), constraint.getWarning().getKey());
					revocationDataIssuedBeforeControlTimeCheckFound = true;
				}
			}
			assertTrue(revocationDataIssuedBeforeControlTimeCheckFound);
		}

		XmlPSV psv = signatureBBB.getPSV();
		assertNotNull(psv);

		assertEquals(Indication.INDETERMINATE, psv.getConclusion().getIndication());
		assertEquals(SubIndication.REVOKED_CA_NO_POE, psv.getConclusion().getSubIndication());
	}

	@Test
	public void revokedCAChainModelTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/ca-revoked.xml"));
		assertNotNull(xmlDiagnosticData);
		
		ConstraintsParameters constraintsParameters = getConstraintsParameters(new File("src/test/resources/policy/default-only-constraint-policy.xml"));
		ModelConstraint modelConstraint = new ModelConstraint();
		modelConstraint.setValue(Model.CHAIN);
		constraintsParameters.setModel(modelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(new EtsiValidationPolicy(constraintsParameters));
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void revokedCAHybridModelTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/ca-revoked.xml"));
		assertNotNull(xmlDiagnosticData);
		
		ConstraintsParameters constraintsParameters = getConstraintsParameters(new File("src/test/resources/policy/default-only-constraint-policy.xml"));
		ModelConstraint modelConstraint = new ModelConstraint();
		modelConstraint.setValue(Model.HYBRID);
		constraintsParameters.setModel(modelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(new EtsiValidationPolicy(constraintsParameters));
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void timestampsSameSecond() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/timestamps_same_second.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		List<Message> warnings = simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId());
		assertFalse(checkMessageValuePresence(warnings, i18nProvider.getMessage(MessageTag.TSV_ASTPTCT_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		List<String> timestampIds = detailedReport.getTimestampIds();
		assertEquals(5, timestampIds.size());
		for (String tspId : timestampIds) {
			assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(tspId));
		}

		assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void timestampsIncorrectOrder() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/timestamps_same_second_incorrect_order.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		List<String> timestampIds = detailedReport.getTimestampIds();
		assertEquals(5, timestampIds.size());
		for (String tspId : timestampIds) {
			assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(tspId));
		}

		assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void hashFailure() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/hash_failure.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_CV_IRDOI_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.LTV_ABSV_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.ARCH_LTVV_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.FAILED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.HASH_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(0, detailedReport.getTimestampIds().size());

		assertEquals(Indication.FAILED, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.HASH_FAILURE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.FAILED, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.HASH_FAILURE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void sigConstraintFailure() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig_constraint_failure.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(0, detailedReport.getTimestampIds().size());

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void signingCertificateNotFoundWithFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/signing_certificate_not_found.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		validationPolicy.getCryptographic().getAlgoExpirationDate().setLevel(Level.WARN);

		SignedAttributesConstraints signedAttributes = validationPolicy.getSignatureConstraints().getSignedAttributes();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		signedAttributes.setSigningCertificatePresent(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
		Date currentTime = sdf.parse("04/05/2016 18:55:00");
		executor.setCurrentTime(currentTime);

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(0, detailedReport.getTimestampIds().size());

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
	}

	@Test
	public void signingCertificateNotFoundWithCryptoCheck() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/signing_certificate_not_found.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
		Date currentTime = sdf.parse("04/05/2016 18:55:00");
		executor.setCurrentTime(currentTime);

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(0, detailedReport.getTimestampIds().size());

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
	}

	@Test
	public void testDSS943() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-943/NotQualified-service.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicyNoRevoc());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
	}

	@Test
	public void testDSS956AllValidationLevels() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/passed_revoked_with_timestamp.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		executor.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);
		Reports reports = executor.execute();
		checkReports(reports);
		SimpleReport simpleReport = reports.getSimpleReport();
		assertFalse(Utils.isCollectionNotEmpty(simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())));

		executor.setValidationLevel(ValidationLevel.TIMESTAMPS);
		reports = executor.execute();
		checkReports(reports);
		simpleReport = reports.getSimpleReport();
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())));

		executor.setValidationLevel(ValidationLevel.LONG_TERM_DATA);
		reports = executor.execute();
		checkReports(reports);
		simpleReport = reports.getSimpleReport();
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())));

		executor.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
		reports = executor.execute();
		checkReports(reports);
		simpleReport = reports.getSimpleReport();
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())));
	}

	@Test
	public void qualification() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/preEIDAS.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.INDETERMINATE_ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
	}

	@Test
	public void qualificationQESig() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/qualifQESig.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
	}

	@Test
	public void qualificationQESigBrexit() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/qualifQESigBrexit.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.INDETERMINATE_QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationReport);
		assertEquals(simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()), 
				SignatureQualification.forURI(signatureValidationReport.getSignatureQuality().getSignatureQualityInformation().get(0)));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void rsa1023() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/rsa1023.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		Date validationDate = diagnosticData.getValidationDate();
		executor.setCurrentTime(validationDate);

		Reports reports = executor.execute();
		DetailedReport detailedReport = reports.getDetailedReport();

		boolean foundWeakAlgo = false;
		List<String> revocationIds = detailedReport.getRevocationIds();
		for (String revocationId : revocationIds) {
			XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(revocationId);
			XmlSAV sav = bbb.getSAV();
			XmlCryptographicValidation cryptographicValidation = sav.getCryptographicValidation();
			if (!cryptographicValidation.isSecure()) {
				foundWeakAlgo = true;
				assertTrue(validationDate.after(cryptographicValidation.getNotAfter()));
			}
		}
		assertTrue(foundWeakAlgo);
		
		SimpleReport simpleReport = reports.getSimpleReport();
		
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicBuildingBlocksIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getBasicBuildingBlocksSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

		XmlSAV sav = signatureBBB.getSAV();
		assertNotNull(sav);

		assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, sav.getConclusion().getSubIndication());

		XmlPCV pcv = signatureBBB.getPCV();
		assertNotNull(pcv);

		assertEquals(Indication.INDETERMINATE, pcv.getConclusion().getIndication());
		assertEquals(SubIndication.NO_POE, pcv.getConclusion().getSubIndication());

		XmlVTS vts = signatureBBB.getVTS();

		assertEquals(Indication.INDETERMINATE, vts.getConclusion().getIndication());
		assertEquals(SubIndication.NO_POE, vts.getConclusion().getSubIndication());

		List<XmlCRS> crss = vts.getCRS();
		assertEquals(2, crss.size());

		assertEquals(Indication.PASSED, crss.get(0).getConclusion().getIndication());

		assertEquals(Indication.INDETERMINATE, crss.get(1).getConclusion().getIndication());
		assertEquals(SubIndication.NO_POE, crss.get(1).getConclusion().getSubIndication());

		boolean revocationDataIssuedBeforeControlTimeCheckFound = false;
		for (XmlConstraint constraint : crss.get(1).getConstraint()) {
			if (MessageTag.PSV_HRDBIBCT.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.PSV_HRDBIBCT_ANS.getId(), constraint.getWarning().getKey());
				revocationDataIssuedBeforeControlTimeCheckFound = true;
			}
		}
		assertTrue(revocationDataIssuedBeforeControlTimeCheckFound);

		XmlPSV psv = signatureBBB.getPSV();
		assertNotNull(psv);

		assertEquals(Indication.INDETERMINATE, psv.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, psv.getConclusion().getSubIndication());

		validateBestSigningTimes(reports);
		checkReports(reports);
	}
	
	@Test
	public void ocspRevocationMessage() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/ocspRevocationMessage.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		Date validationDate = diagnosticData.getValidationDate();
		executor.setCurrentTime(validationDate);

		executor.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
		Reports reports = executor.execute();
		
		DetailedReport detailedReport = reports.getDetailedReport();
		
		// Extract the build block where the verification failed
		XmlBasicBuildingBlocks basicBuildingBlockById = detailedReport.getBasicBuildingBlockById("R-F104CADD12E8C96491EB3F95667AFB7E594162A461F968CE2D488C32E6A18624");

		// Get the Error Message as well as any extra information
		XmlSAV sav = basicBuildingBlockById.getSAV();
		XmlConstraint xmlConstraint = sav.getConstraint().get(0);
		XmlMessage error = xmlConstraint.getError();
		
		assertEquals(MessageTag.ASCCM_PKSK_ANS.name(), error.getKey());

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId())); // OCSP Cert not found

		executor.setValidationLevel(ValidationLevel.LONG_TERM_DATA);
		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId())); // OCSP Cert not found

		executor.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);
		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId())); // Crypto for OCSP
																												  // Cert not found -->
		                                                                                                          // No acceptable revocation
	}
	
	@Test
	public void notTrustedOcspTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/lt-level-with-not-trusted-ocsp.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());
		
		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void qualificationNA() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/qualifNA.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.NA, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationReport);
		assertEquals(simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()), 
				SignatureQualification.forURI(signatureValidationReport.getSignatureQuality().getSignatureQualityInformation().get(0)));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void noSigningTime() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/no-signing-date.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.INDETERMINATE_QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testCertChain() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/qualifNA.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(1, simpleReport.getJaxbModel().getSignaturesCount());
		XmlCertificateChain certificateChain = simpleReport.getCertificateChain(simpleReport.getFirstSignatureId());
		assertNotNull(certificateChain);
		assertTrue(Utils.isCollectionNotEmpty(certificateChain.getCertificate()));
		assertEquals(3, certificateChain.getCertificate().size());
		ByteArrayOutputStream s = new ByteArrayOutputStream();
		JAXB.marshal(simpleReport.getJaxbModel(), s);

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testWithoutCertChain() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/qualifNAWithoutCertChain.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(1, simpleReport.getJaxbModel().getSignaturesCount());
		XmlCertificateChain certificateChain = simpleReport.getCertificateChain(simpleReport.getFirstSignatureId());
		assertNotNull(certificateChain);
		assertTrue(Utils.isCollectionEmpty(certificateChain.getCertificate()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testMultiSigs() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/multi-sign.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(4, simpleReport.getJaxbModel().getSignaturesCount());

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(4, detailedReport.getSignatureIds().size());

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testCounterSignature() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/counter-signature-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(2, simpleReport.getJaxbModel().getSignaturesCount());
		
		String firstSigId = simpleReport.getSignatureIdList().get(0);
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(firstSigId));
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(firstSigId));

		String secondSigId = simpleReport.getSignatureIdList().get(1);
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(secondSigId));
		assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(secondSigId));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(2, detailedReport.getSignatureIds().size());

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testValidCounterSignature() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/counter-signature-valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(2, simpleReport.getJaxbModel().getSignaturesCount());
		
		String firstSigId = simpleReport.getSignatureIdList().get(0);
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(firstSigId));

		String secondSigId = simpleReport.getSignatureIdList().get(1);
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(secondSigId));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testSAVWithSignatureConstraints() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/counter-signature-valid-diag-data.xml"));
		assertNotNull(diagnosticData);
		
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		
		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
		signatureConstraints.getSignedAttributes().setSignerLocation(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(2, simpleReport.getJaxbModel().getSignaturesCount());
		
		String firstSigId = simpleReport.getSignatureIdList().get(0);
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(firstSigId));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(firstSigId));
		
		List<Message> errors = simpleReport.getAdESValidationErrors(firstSigId);
		assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_SAV_ISQPSLP_ANS)));

		String secondSigId = simpleReport.getSignatureIdList().get(1);
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(secondSigId));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testSAVWithCounterSignatureConstraints() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/counter-signature-valid-diag-data.xml"));
		assertNotNull(diagnosticData);
		
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		
		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getCounterSignatureConstraints();
		signatureConstraints.getSignedAttributes().setContentTimeStamp(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(2, simpleReport.getJaxbModel().getSignaturesCount());
		
		String firstSigId = simpleReport.getSignatureIdList().get(0);
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(firstSigId));

		String secondSigId = simpleReport.getSignatureIdList().get(1);
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(secondSigId));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(secondSigId));
		
		List<Message> errors = simpleReport.getAdESValidationErrors(secondSigId);
		assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_SAV_ISQPCTSIP_ANS)));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void multiFiles() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/asic-e-multi-files-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void multiFilesNoManifest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/asic-e-multi-files-no-manifest-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_IMFP_ASICE_ANS)));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void asicEXades() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/asic-e-xades-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void webSiteAuth() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag_data_WSA.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.NOT_ADES, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationReport);
		assertEquals(simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()), 
				SignatureQualification.forURI(signatureValidationReport.getSignatureQuality().getSignatureQualityInformation().get(0)));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void doubleAsieAndQCType() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag_data_double_ASIE_qctype.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		// see test case 5.1.5
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.UNKNOWN_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void doubleAsie() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag_data_double_ASIE.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.ADESEAL_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationReport);
		assertEquals(simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()), 
				SignatureQualification.forURI(signatureValidationReport.getSignatureQuality().getSignatureQualityInformation().get(0)));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void asicSXades() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/asic-s-xades-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void commisign() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/commisign.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.UNKNOWN, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		// no qualifiers
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationReport);
		assertEquals(simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()), 
				SignatureQualification.forURI(signatureValidationReport.getSignatureQuality().getSignatureQualityInformation().get(0)));

		checkReports(reports);
	}

	@Test
	public void testDSS1330() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-1330-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		TimestampWrapper earliestTimestamp = reports.getDiagnosticData().getTimestampById("T-950D06E9BC8B0CDB73D88349F14D3BC702BF4947752A121A940EE03639C1249D");
		TimestampWrapper secondTimestamp = reports.getDiagnosticData().getTimestampById("T-88E49182915AC09C4734996E127BFB04944E485EFC29C89D7822250A57FCC2FB");
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		ValidationObjectListType signatureValidationObjects = etsiValidationReport.getSignatureValidationObjects();
		assertNotNull(signatureValidationObjects);
		assertTrue(Utils.isCollectionNotEmpty(signatureValidationObjects.getValidationObject()));
		for (ValidationObjectType validationObject : signatureValidationObjects.getValidationObject()) {
			if (validationObject.getPOE() != null) {
				VOReferenceType poeObjectReference = validationObject.getPOE().getPOEObject();
				if (earliestTimestamp.getId().equals(validationObject.getId())) {
					assertEquals(secondTimestamp.getProductionTime(), validationObject.getPOE().getPOETime());
					Object poeObject = poeObjectReference.getVOReference().get(0);
					assertTrue(poeObject instanceof ValidationObjectType);
					assertEquals(secondTimestamp.getId(), ((ValidationObjectType) poeObject).getId());
				} else if (poeObjectReference != null) {
					assertEquals(earliestTimestamp.getProductionTime(), validationObject.getPOE().getPOETime());
					Object poeObject = poeObjectReference.getVOReference().get(0);
					assertTrue(poeObject instanceof ValidationObjectType);
					assertEquals(earliestTimestamp.getId(), ((ValidationObjectType) poeObject).getId());
				} else {
					assertEquals(diagnosticData.getValidationDate(), validationObject.getPOE().getPOETime());
				}
			}
		}

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testDSS1330CryptoWarn() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-1330-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicyCryptoWarn());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testTLOK() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/tl-ok.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadTLPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		checkReports(reports);
	}

	@Test
	public void testTLKO() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/tl-ko.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadTLPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.FAILED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

		checkReports(reports);
	}
	
	@Test
	public void structureValidationFailureTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/xades-structure-failure.xml"));

		List<String> messages = diagnosticData.getSignatures().get(0).getStructuralValidation().getMessages();
		assertTrue(Utils.isCollectionNotEmpty(messages));

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());
		
		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId())); // WARN level by default
		
		List<Message> warnings = simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(warnings, i18nProvider.getMessage(MessageTag.BBB_SAV_ISSV_ANS)));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);
		
		XmlSAV sav = signatureBBB.getSAV();
		assertNotNull(sav);
		
		boolean structureWarnFound = false;
		List<XmlConstraint> constraints = sav.getConstraint();
		for (XmlConstraint constraint : constraints) {
			if (MessageTag.BBB_SAV_ISSV.name().equals(constraint.getName().getKey())) {
				assertTrue(constraint.getAdditionalInfo().contains(messages.get(0)));
				structureWarnFound = true;
			}
		}
		assertTrue(structureWarnFound);
	}
	
	@Test
	public void structuralValidationFailLevelTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/xades-structure-failure.xml"));
		
		List<String> messages = diagnosticData.getSignatures().get(0).getStructuralValidation().getMessages();
		assertTrue(Utils.isCollectionNotEmpty(messages));

		ValidationPolicy policy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
		SignatureConstraints signatureConstraints = policy.getSignatureConstraints();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		signatureConstraints.setStructuralValidation(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(policy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.BBB_SAV_ISSV_ANS)));
	}
	
	@Test
	public void signedPropertiesMissedTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/signedProperties_missed.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());
		
		Reports reports = executor.execute();
		// reports.print();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlSAV sav = signatureBBB.getSAV();
		assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

		checkReports(reports);
	}
	
	@Test
	public void signedPropertiesMissedNotStrictPolicyTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/signedProperties_missed.xml"));
		assertNotNull(diagnosticData);
		
		LevelConstraint passLevel = new LevelConstraint();
		passLevel.setLevel(Level.WARN);
		ValidationPolicy policy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
		SignatureConstraints signatureConstraints = policy.getSignatureConstraints();
		signatureConstraints.getSignedAttributes().setMessageDigestOrSignedPropertiesPresent(passLevel);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(policy);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		
		Reports reports = executor.execute();
		// reports.print();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertNull(simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		List<Message> warnings = simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId());
		assertEquals(1, warnings.size());
		assertTrue(checkMessageValuePresence(warnings, i18nProvider.getMessage(MessageTag.BBB_SAV_ISQPMDOSPP_ANS)));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlSAV sav = signatureBBB.getSAV();
		assertEquals(Indication.PASSED, sav.getConclusion().getIndication());

		checkReports(reports);
		
	}

	@Test
	public void testTLNoSigCertEmptyPolicy() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/tl-no-signing-cert.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(new EtsiValidationPolicy(new ConstraintsParameters()));
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		// reports.print();

		checkReports(reports);
	}
	
	@Test
	public void LTAandAIAforTrustAnchor() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/LTAandAIAforTrustAnchor.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.UNKNOWN, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicBuildingBlocksIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicBuildingBlocksSubIndication(detailedReport.getFirstSignatureId()));
		assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

		checkReports(reports);
	}
	
	@Test
	public void revocInfoOutOfBoundsTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/revoc-info-out-of-bounds.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));
	}
	
	@Test
	public void expiredCertsRevocationInfoTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/expired-certs-revocation-info.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		assertNotNull(signingCertificate);
		List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
		assertEquals(1, certificateRevocationData.size());
		CertificateRevocationWrapper certificateRevocation = certificateRevocationData.get(0);

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		List<XmlSubXCV> subXCV = xcv.getSubXCV();
		assertEquals(2, subXCV.size());

		XmlSubXCV xmlSubXCV = subXCV.get(0);
		XmlCRS crs = xmlSubXCV.getCRS();
		assertNotNull(crs);

		List<XmlRAC> racs = crs.getRAC();
		assertEquals(1, racs.size());

		XmlRAC xmlRAC = racs.get(0);
		boolean consistencyCheckFound = false;
		for (XmlConstraint constraint : xmlRAC.getConstraint()) {
			if (MessageTag.BBB_XCV_IRDC.getId().equals(constraint.getName().getKey())) {
				assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_TL,
						ValidationProcessUtils.getFormattedDate(certificateRevocation.getThisUpdate()),
						ValidationProcessUtils.getFormattedDate(certificateRevocation.getSigningCertificate().getCertificateTSPServiceExpiredCertsRevocationInfo()),
						ValidationProcessUtils.getFormattedDate(signingCertificate.getNotBefore()),
						ValidationProcessUtils.getFormattedDate(signingCertificate.getNotAfter())), constraint.getAdditionalInfo());
				consistencyCheckFound = true;
			}
		}
		assertTrue(consistencyCheckFound);
	}
	
	@Test
	public void expiredCertsOnCRLExtension() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/expired-certs-on-crl-extension.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		assertNotNull(signingCertificate);
		List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
		assertEquals(1, certificateRevocationData.size());
		CertificateRevocationWrapper certificateRevocation = certificateRevocationData.get(0);

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		List<XmlSubXCV> subXCV = xcv.getSubXCV();
		assertEquals(2, subXCV.size());

		XmlSubXCV xmlSubXCV = subXCV.get(0);
		XmlCRS crs = xmlSubXCV.getCRS();
		assertNotNull(crs);

		List<XmlRAC> racs = crs.getRAC();
		assertEquals(1, racs.size());

		XmlRAC xmlRAC = racs.get(0);
		boolean consistencyCheckFound = false;
		for (XmlConstraint constraint : xmlRAC.getConstraint()) {
			if (MessageTag.BBB_XCV_IRDC.getId().equals(constraint.getName().getKey())) {
				assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_CRL,
						ValidationProcessUtils.getFormattedDate(certificateRevocation.getThisUpdate()),
						ValidationProcessUtils.getFormattedDate(certificateRevocation.getExpiredCertsOnCRL()),
						ValidationProcessUtils.getFormattedDate(signingCertificate.getNotBefore()),
						ValidationProcessUtils.getFormattedDate(signingCertificate.getNotAfter())), constraint.getAdditionalInfo());
				consistencyCheckFound = true;
			}
		}
		assertTrue(consistencyCheckFound);
	}

	@Test
	public void expiredCertsRevocationInfoAndExpiredCertsOnCRLTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/expired-certs-revocation-info-with-expired-certs-on-crl.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		assertNotNull(signingCertificate);
		List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
		assertEquals(1, certificateRevocationData.size());
		CertificateRevocationWrapper certificateRevocation = certificateRevocationData.get(0);

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		List<XmlSubXCV> subXCV = xcv.getSubXCV();
		assertEquals(2, subXCV.size());

		XmlSubXCV xmlSubXCV = subXCV.get(0);
		XmlCRS crs = xmlSubXCV.getCRS();
		assertNotNull(crs);

		List<XmlRAC> racs = crs.getRAC();
		assertEquals(1, racs.size());

		XmlRAC xmlRAC = racs.get(0);
		boolean consistencyCheckFound = false;
		for (XmlConstraint constraint : xmlRAC.getConstraint()) {
			if (MessageTag.BBB_XCV_IRDC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_NOT_AFTER_AFTER,
						ValidationProcessUtils.getFormattedDate(certificateRevocation.getExpiredCertsOnCRL()),
						ValidationProcessUtils.getFormattedDate(signingCertificate.getNotBefore()),
						ValidationProcessUtils.getFormattedDate(signingCertificate.getNotAfter())), constraint.getAdditionalInfo());
				consistencyCheckFound = true;
			}
		}
		assertTrue(consistencyCheckFound);
	}

	@Test
	public void testPdfSignatureDictionary() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag_data_pdfsigdict.xml"));
		assertNotNull(xmlDiagnosticData);
		
		List<eu.europa.esig.dss.diagnostic.jaxb.XmlSignature> xmlSignatures = xmlDiagnosticData.getSignatures();
		assertNotNull(xmlSignatures);
		for (eu.europa.esig.dss.diagnostic.jaxb.XmlSignature signature : xmlSignatures) {
			XmlPDFRevision pdfRevision = signature.getPDFRevision();
			assertNotNull(pdfRevision);
			XmlPDFSignatureDictionary pdfSignatureDictionary = pdfRevision.getPDFSignatureDictionary();
			assertNotNull(pdfSignatureDictionary);
			List<BigInteger> byteRange = pdfSignatureDictionary.getSignatureByteRange().getValue();
			assertNotNull(byteRange);
			assertEquals(4, byteRange.size());
			assertEquals(-1, byteRange.get(1).compareTo(byteRange.get(2)));
		}

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadTLPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);
		eu.europa.esig.dss.diagnostic.DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData.getAllSignatures());
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(xmlSignatures.get(0).getId());
		assertNotNull(signatureWrapper);
		List<BigInteger> byteRange = signatureWrapper.getSignatureByteRange();
		assertNotNull(byteRange);
		assertEquals(4, byteRange.size());
		List<BigInteger> xmlByteRange = xmlSignatures.get(0).getPDFRevision().getPDFSignatureDictionary().getSignatureByteRange().getValue();
		assertEquals(xmlByteRange.get(0), byteRange.get(0));
		assertEquals(xmlByteRange.get(1), byteRange.get(1));
		assertEquals(xmlByteRange.get(2), byteRange.get(2));
		assertEquals(xmlByteRange.get(3), byteRange.get(3));

		checkReports(reports);

	}

	@Test
	public void testDSS1647() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/dss-1647.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testDSS1469() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/dss-1469-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		checkReports(reports);
	}

	@Test
	public void testDSS1670() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/dss-1670-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		checkReports(reports);
	}

	@Test
	public void testDSS1670CryptoWarn() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/dss-1670-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicyCryptoWarn());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		checkReports(reports);
	}

	@Test
	public void cryptoNoPOETest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag_data_crypto_no_poe.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		checkReports(reports);
		
	}
	
	@Test
	public void dss1635Test() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/dss-1635-diag-data.xml"));
		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		ValidationPolicy defaultPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
		List<Algo> algos = defaultPolicy.getCryptographic().getAlgoExpirationDate().getAlgos();
		for (Algo algo : algos) {
			if ("SHA1".equals(algo.getValue())) {
				algo.setDate("2014");
				break;
			}
		}
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		// current year returns a first day
		for (Algo algo : algos) {
			if ("SHA1".equals(algo.getValue())) {
				algo.setDate("2013");
				break;
			}
		}

		executor.setValidationPolicy(defaultPolicy);
		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		checkReports(reports);
		
	}
	
	@Test
	public void dss1768Test() throws Exception {
		// AbstractCryptographicCheck must use getName() for encryption algos (ex. PLAIN-ECDSA)
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-1768/dss-1768-plain-ecdsa.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		checkReports(reports);
	}
	
	@Test
	public void dss1768ExpiredTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-1768/dss-1768-plain-ecdsa160.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		checkReports(reports);
	}
	
	@Test
	public void dss1768SmallKeySizeTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-1768/dss-1768-plain-ecdsa128.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlSAV sav = signatureBBB.getSAV();
		assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, sav.getConclusion().getSubIndication());
		assertFalse(sav.getCryptographicValidation().isSecure());
		
		checkReports(reports);
	}
	
	@Test
	public void dss1988Test() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/dss-1988.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		List<SignatureValidationReportType> signatureValidationReports = etsiValidationReport.getSignatureValidationReport();
		assertEquals(1, signatureValidationReports.size());
		
		SignatureValidationReportType signatureValidationReport = signatureValidationReports.get(0);
		ValidationTimeInfoType validationTimeInfo = signatureValidationReport.getValidationTimeInfo();
		assertNotNull(validationTimeInfo);
		assertEquals(diagnosticData.getValidationDate(), validationTimeInfo.getValidationTime());
		
		POEType bestSignatureTime = validationTimeInfo.getBestSignatureTime();
		assertNotNull(bestSignatureTime);
		
		assertEquals(TypeOfProof.VALIDATION, bestSignatureTime.getTypeOfProof());
		VOReferenceType poeObject = bestSignatureTime.getPOEObject();
		assertNotNull(poeObject);
		
		List<Object> voReference = poeObject.getVOReference();
		assertNotNull(voReference);
		assertEquals(1, voReference.size());
		
		Object timestampObject = voReference.get(0);
		assertTrue(timestampObject instanceof ValidationObjectType);
		ValidationObjectType timestampValidationObject = (ValidationObjectType) timestampObject;
		String timestampId = timestampValidationObject.getId();
		assertNotNull(timestampId);
		
		ValidationObjectListType signatureValidationObjects = etsiValidationReport.getSignatureValidationObjects();
		assertNotNull(signatureValidationObjects);
		assertTrue(Utils.isCollectionNotEmpty(signatureValidationObjects.getValidationObject()));
		for (ValidationObjectType validationObject : signatureValidationObjects.getValidationObject()) {
			if (timestampId.equals(validationObject.getId())) {
				timestampValidationObject = validationObject;
				break;
			}
		}
		
		assertEquals(ObjectType.TIMESTAMP, timestampValidationObject.getObjectType());
		POEProvisioningType poeProvisioning = timestampValidationObject.getPOEProvisioning();
		assertNotNull(poeProvisioning);
		
		List<VOReferenceType> timestampedObjects = poeProvisioning.getValidationObject();
		assertTrue(Utils.isCollectionNotEmpty(timestampedObjects));
		
		List<SignatureReferenceType> signatureReferences = poeProvisioning.getSignatureReference();
		assertEquals(1, signatureReferences.size());
		
		XmlSignatureDigestReference signatureDigestReference = diagnosticData.getSignatures().get(0).getSignatureDigestReference();
		
		SignatureReferenceType signatureReferenceType = signatureReferences.get(0);
		assertEquals(signatureDigestReference.getCanonicalizationMethod(), signatureReferenceType.getCanonicalizationMethod());
		assertEquals(signatureDigestReference.getDigestMethod(), DigestAlgorithm.forXML(signatureReferenceType.getDigestMethod()));
		assertArrayEquals(signatureDigestReference.getDigestValue(), signatureReferenceType.getDigestValue());
		
		DetailedReport detailedReport = reports.getDetailedReport();
		
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlSAV sav = signatureBBB.getSAV();
		assertEquals(1, sav.getConclusion().getErrors().size());

		XmlCryptographicValidation cryptographicValidation = sav.getCryptographicValidation();
		assertEquals(SignatureAlgorithm.RSA_SHA1, SignatureAlgorithm.forXML(cryptographicValidation.getAlgorithm().getUri()));
		assertEquals("2048", cryptographicValidation.getAlgorithm().getKeyLength());
		
		checkReports(reports);
	}
	
	@Test
	public void padesMultiSignerInfoPresentTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/pades-multi-signer-info.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);
		
		XmlFC fc = signatureBBB.getFC();
		assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());
		
		boolean signerInformationCheckFound = false;
		List<XmlConstraint> constraints = fc.getConstraint();
		for (XmlConstraint constrant : constraints) {
			if (MessageTag.BBB_FC_IOSIP.name().equals(constrant.getName().getKey())) {
				assertEquals(MessageTag.BBB_FC_IOSIP_ANS.name(), constrant.getError().getKey());
				assertEquals(XmlStatus.NOT_OK, constrant.getStatus());
				signerInformationCheckFound = true;
			}
		}
		assertTrue(signerInformationCheckFound);
	}
	
	@Test
	public void padesMultiSignerInfoPresentWarnTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/pades-multi-signer-info.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		EtsiValidationPolicy defaultPolicy = (EtsiValidationPolicy) ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
		BasicSignatureConstraints basicSignatureConstraints = defaultPolicy.getSignatureConstraints().getBasicSignatureConstraints();
		LevelConstraint signerInformationStore = basicSignatureConstraints.getSignerInformationStore();
		signerInformationStore.setLevel(Level.WARN);
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		List<Message> warnings = simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(warnings,
				i18nProvider.getMessage(MessageTag.BBB_FC_IOSIP_ANS)));
	}

	@Test
	public void padesFieldsOverlappingFailTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag_data_pdf_fields_overlap.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		EtsiValidationPolicy defaultPolicy = (EtsiValidationPolicy) ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
		BasicSignatureConstraints basicSignatureConstraints = defaultPolicy.getSignatureConstraints().getBasicSignatureConstraints();
		LevelConstraint pdfAnnotationOverlap = basicSignatureConstraints.getPdfAnnotationOverlap();
		pdfAnnotationOverlap.setLevel(Level.FAIL);
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		for (String signatureId : simpleReport.getSignatureIdList()) {
			assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(signatureId));
			assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(signatureId));
			
			List<Message> errors = simpleReport.getAdESValidationErrors(signatureId);
			assertTrue(checkMessageValuePresence(errors,
					i18nProvider.getMessage(MessageTag.BBB_FC_IAOD_ANS, "[1]")));
		}
	}

	@Test
	public void padesFieldsOverlappingWarnTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag_data_pdf_fields_overlap.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		EtsiValidationPolicy defaultPolicy = (EtsiValidationPolicy) ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
		BasicSignatureConstraints basicSignatureConstraints = defaultPolicy.getSignatureConstraints().getBasicSignatureConstraints();
		LevelConstraint pdfAnnotationOverlap = basicSignatureConstraints.getPdfAnnotationOverlap();
		pdfAnnotationOverlap.setLevel(Level.WARN);
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		for (String signatureId : simpleReport.getSignatureIdList()) {
			assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(signatureId));
			
			List<Message> warnings = simpleReport.getAdESValidationWarnings(signatureId);
			assertTrue(checkMessageValuePresence(warnings,
					i18nProvider.getMessage(MessageTag.BBB_FC_IAOD_ANS, "[1]")));
		}
	}

	@Test
	public void padesVisualDifferenceFailTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag_data_pdf_visual_difference.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		EtsiValidationPolicy defaultPolicy = (EtsiValidationPolicy) ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
		BasicSignatureConstraints basicSignatureConstraints = defaultPolicy.getSignatureConstraints().getBasicSignatureConstraints();
		LevelConstraint pdfVisualDifference = basicSignatureConstraints.getPdfVisualDifference();
		pdfVisualDifference.setLevel(Level.FAIL);
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		for (String signatureId : simpleReport.getSignatureIdList()) {
			assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(signatureId));
			assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(signatureId));
			
			List<Message> errors = simpleReport.getAdESValidationErrors(signatureId);
			assertTrue(checkMessageValuePresence(errors,
					i18nProvider.getMessage(MessageTag.BBB_FC_IVDBSFR_ANS, "[1]")));
		}
	}

	@Test
	public void padesVisualDifferenceWarnTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag_data_pdf_visual_difference.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		EtsiValidationPolicy defaultPolicy = (EtsiValidationPolicy) ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
		BasicSignatureConstraints basicSignatureConstraints = defaultPolicy.getSignatureConstraints().getBasicSignatureConstraints();
		LevelConstraint pdfVisualDifference = basicSignatureConstraints.getPdfVisualDifference();
		pdfVisualDifference.setLevel(Level.WARN);
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		for (String signatureId : simpleReport.getSignatureIdList()) {
			assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(signatureId));
			
			List<Message> warnings = simpleReport.getAdESValidationWarnings(signatureId);
			assertTrue(checkMessageValuePresence(warnings,
					i18nProvider.getMessage(MessageTag.BBB_FC_IVDBSFR_ANS, "[1]")));
		}
	}
	
	@Test
	public void signatureNotIntactTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/signature-not-intact.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CRYPTO_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void rsa2047Test() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-1938/rsa2047-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void rsa2047RevokedTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-1938/rsa2047-diag-data-revoked.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
		assertNotNull(validationProcessBasicSignature.getTitle());
		assertNotNull(validationProcessBasicSignature.getProofOfExistence());

		boolean x509CVCheckFound = false;
		boolean x509RevokedCheckFound = false;
		boolean tstAfterRevocationTimeCheckFound = false;
		boolean basicSignatureValidationCheckFound = false;
		for (XmlConstraint constraint : validationProcessBasicSignature.getConstraint()) {
			if (MessageTag.BSV_IXCVRC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				x509CVCheckFound = true;
			} else if (MessageTag.BSV_ISCRAVTC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				x509RevokedCheckFound = true;
			} else if (MessageTag.BSV_ICTGTNASCRT.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				tstAfterRevocationTimeCheckFound = true;
			} else if (MessageTag.ADEST_ROBVPIIC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				basicSignatureValidationCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(x509CVCheckFound);
		assertTrue(x509RevokedCheckFound);
		assertTrue(tstAfterRevocationTimeCheckFound);
		assertTrue(basicSignatureValidationCheckFound);

		assertFalse(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.ADEST_ROBVPIIC_ANS)));
		assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCR_ANS)));
		assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getWarnings()),
				i18nProvider.getMessage(MessageTag.BSV_ICTGTNASCRT_ANS)));
	}

	@Test
	public void rsa2047ExpiredTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-1938/rsa2047-diag-data-expired.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.EXPIRED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
		assertNotNull(validationProcessBasicSignature.getTitle());
		assertNotNull(validationProcessBasicSignature.getProofOfExistence());

		boolean x509CVCheckFound = false;
		boolean x509ExpiredCheckFound = false;
		boolean tstAfterExpirationTimeCheckFound = false;
		boolean basicSignatureValidationCheckFound = false;
		for (XmlConstraint constraint : validationProcessBasicSignature.getConstraint()) {
			if (MessageTag.BSV_IXCVRC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				x509CVCheckFound = true;
			} else if (MessageTag.BSV_IVTAVRSC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				x509ExpiredCheckFound = true;
			} else if (MessageTag.BSV_ICTGTNASCET.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				tstAfterExpirationTimeCheckFound = true;
			} else if (MessageTag.ADEST_ROBVPIIC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				basicSignatureValidationCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(x509CVCheckFound);
		assertTrue(x509ExpiredCheckFound);
		assertTrue(tstAfterExpirationTimeCheckFound);
		assertTrue(basicSignatureValidationCheckFound);

		assertFalse(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.ADEST_ROBVPIIC_ANS)));
		assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
		assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getWarnings()),
				i18nProvider.getMessage(MessageTag.BSV_ICTGTNASCET_ANS)));
	}

	@Test
	public void rsa2047CryptoConstraintFailureTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/DSS-1938/rsa2047-diag-data-crypto-constraint-failure.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void md5Test() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/md5-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		// validation on 2005-01-20
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void md5ValidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/md5-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		// validation on 2004-01-20
		Date validationDate = diagnosticData.getValidationDate();
		Calendar cal = Calendar.getInstance();
		cal.setTime(validationDate);
		cal.add(Calendar.YEAR, -1);
		executor.setCurrentTime(cal.getTime());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void certNotBeforeAndCRLSameTimeTest() throws Exception {
		// DSS-1932
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/cert-and-revoc-same-time.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void sigTSTAtCertExpirationTime() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-tst-at-sign-cert-expiration.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void dss2025() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/DSS-2025/diag-sign-cert-tst-not-unique.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.WARN);
		validationPolicy.getTimestampConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setIssuerName(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0);
		assertEquals(Indication.PASSED, xmlTimestamp.getIndication());
		assertTrue(checkMessageValuePresence(convertMessages(xmlTimestamp.getAdESValidationDetails().getWarning()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_DCIDNMSDNIC_ANS)));
	}
	
	@Test
	public void dss2025TstFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/DSS-2025/diag-sign-cert-tst-not-unique.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		TimestampConstraints timestampConstraints = defaultPolicy.getTimestampConstraints();
		SignedAttributesConstraints signedAttributes = timestampConstraints.getSignedAttributes();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		signedAttributes.setUnicitySigningCertificate(levelConstraint);

		levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		defaultPolicy.getTimestampConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setIssuerName(levelConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		 
		List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
		assertEquals(1, usedTimestamps.size());
		String tstId = usedTimestamps.get(0).getId();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(tstId));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicTimestampValidationSubIndication(tstId));
	}
	
	@Test
	public void dss2025Unique() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/DSS-2025/diag-sign-cert-unique.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		SignedAttributesConstraints sigSignedAttributes = signatureConstraints.getSignedAttributes();
		sigSignedAttributes.setUnicitySigningCertificate(levelConstraint);
		TimestampConstraints timestampConstraints = defaultPolicy.getTimestampConstraints();
		SignedAttributesConstraints tstSignedAttributes = timestampConstraints.getSignedAttributes();
		tstSignedAttributes.setUnicitySigningCertificate(levelConstraint);

		levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		defaultPolicy.getTimestampConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setIssuerName(levelConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void dss2025WithOrphanFail() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/DSS-2025/diag-sign-cert-with-orphan.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		SignedAttributesConstraints sigSignedAttributes = signatureConstraints.getSignedAttributes();
		sigSignedAttributes.setUnicitySigningCertificate(levelConstraint);

		levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		defaultPolicy.getTimestampConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setIssuerName(levelConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void dss2025AnotherCertSignCertRef() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/DSS-2025/diag-sign-cert-another-cert.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.WARN);
		validationPolicy.getTimestampConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setIssuerName(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void dss2025TstIssuerNameFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/DSS-2025/diag-sign-cert-tst-not-unique.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		validationPolicy.getTimestampConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setIssuerName(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0);
		assertEquals(Indication.INDETERMINATE, xmlTimestamp.getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlTimestamp.getSubIndication());
		assertTrue(checkMessageValuePresence(convertMessages(xmlTimestamp.getAdESValidationDetails().getError()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_DCIDNMSDNIC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
		assertNotNull(tstBBB);
		
		XmlXCV xcv = tstBBB.getXCV();
		assertNotNull(xcv);
		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(2, subXCVs.size());

		XmlSubXCV xmlSubXCV = subXCVs.get(0);
		boolean issuerNameCheckFound = false;
		for (XmlConstraint xmlConstraint : xmlSubXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_DCIDNMSDNIC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_DCIDNMSDNIC_ANS.getId(), xmlConstraint.getError().getKey());
				issuerNameCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
			}
		}
		assertTrue(issuerNameCheckFound);
	}
	
	// DSS-2056
	@Test
	public void certHashNotPresentWithWarnLevel() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		RevocationConstraints revocationConstraints = defaultPolicy.getRevocationConstraints();
		revocationConstraints.setOCSPCertHashPresent(levelConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		boolean refFoundCheckFound = false;
		boolean refIntactCheckFound = false;
		boolean messageImprintFoundCheckFound = false;
		boolean messageImprintIntactCheckFound = false;
		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		for (XmlConstraint constraint : sigBBB.getCV().getConstraint()) {
			if (MessageTag.BBB_CV_IRDOF.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				assertNotNull(constraint.getAdditionalInfo());
				refFoundCheckFound = true;
			} else if (MessageTag.BBB_CV_IRDOI.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				assertNotNull(constraint.getAdditionalInfo());
				refIntactCheckFound = true;
			}
		}

		List<String> timestampIds = detailedReport.getTimestampIds();
		assertEquals(1, timestampIds.size());
		XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestampIds.get(0));
		for (XmlConstraint constraint : tstBBB.getCV().getConstraint()) {
			if (MessageTag.BBB_CV_TSP_IRDOF.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				assertNull(constraint.getAdditionalInfo());
				messageImprintFoundCheckFound = true;
			} else if (MessageTag.BBB_CV_TSP_IRDOI.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				assertNull(constraint.getAdditionalInfo());
				messageImprintIntactCheckFound = true;
			}
		}
		assertTrue(refFoundCheckFound);
		assertTrue(refIntactCheckFound);
		assertTrue(messageImprintFoundCheckFound);
		assertTrue(messageImprintIntactCheckFound);
	}
	
	@Test
	public void certHashNotPresentWithFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		RevocationConstraints revocationConstraints = defaultPolicy.getRevocationConstraints();
		revocationConstraints.setOCSPCertHashPresent(levelConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void certHashDoesNotMatchWithFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		RevocationConstraints revocationConstraints = defaultPolicy.getRevocationConstraints();
		revocationConstraints.setOCSPCertHashMatch(levelConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		// check is not executed if certHash is not present
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void certHashPresentAndDoesNotMatchWithFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);
		
		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate certificate = xmlSignature.getSigningCertificate().getCertificate();
		XmlRevocation revocation = certificate.getRevocations().get(0).getRevocation();
		revocation.setCertHashExtensionPresent(true);
		revocation.setCertHashExtensionMatch(false);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		RevocationConstraints revocationConstraints = defaultPolicy.getRevocationConstraints();
		revocationConstraints.setOCSPCertHashMatch(levelConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	//see DSS-2070
	@Test
	public void tLevelSigWithSignCertExpiredTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/dss-2070.xml"));
		assertNotNull(diagnosticData);
		
		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));
		
		assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		
		XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
		assertEquals(Indication.PASSED, validationProcessLongTermData.getConclusion().getIndication());
		
		boolean sigTimeNotBeforeCertIssuanceExecuted = false;
		boolean sigTimeBeforeCertExpirationExecuted = false;
		boolean nextStepsExecuted = false;
		for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
			if (MessageTag.TSV_IBSTAIDOSC.name().equals(constraint.getName().getKey())) {
				sigTimeNotBeforeCertIssuanceExecuted = true;
			} else if (MessageTag.TSV_IBSTBCEC.name().equals(constraint.getName().getKey())) {
				sigTimeBeforeCertExpirationExecuted = true;
			} else if (sigTimeNotBeforeCertIssuanceExecuted || sigTimeBeforeCertExpirationExecuted) {
				nextStepsExecuted = true;
			}
			assertNotEquals(XmlStatus.NOT_OK, constraint.getStatus());
		}
		assertTrue(sigTimeNotBeforeCertIssuanceExecuted);
		assertTrue(sigTimeBeforeCertExpirationExecuted);
		assertTrue(nextStepsExecuted);
		
		assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
	}
	
	@Test
	public void dss2115ValidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/DSS-2115/dss-2115-valid.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getSignedAttributes().setSigningCertificateRefersCertificateChain(levelConstraint);
		signatureConstraints.getSignedAttributes().setReferencesToAllCertificateChainPresent(levelConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void dss2115WithAdditionalRefTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/DSS-2115/dss-2115-additional-ref.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getSignedAttributes().setSigningCertificateRefersCertificateChain(levelConstraint);
		signatureConstraints.getSignedAttributes().setReferencesToAllCertificateChainPresent(levelConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_SAV_DSCACRCC_ANS)));
	}
	
	@Test
	public void dss2115WithMissingRefTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/DSS-2115/dss-2115-missing-ref.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getSignedAttributes().setSigningCertificateRefersCertificateChain(levelConstraint);
		signatureConstraints.getSignedAttributes().setReferencesToAllCertificateChainPresent(levelConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_SAV_ACPCCRSCA_ANS)));
	}
	
	@Test
	public void noRevocationAccessPointsTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/no-revoc-access-points.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setRevocationInfoAccessPresent(levelConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_XCV_REVOC_PRES_ANS)));
	}

	@Test
	public void surnameNameValidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setSurname("Freeman");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("Freeman");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setSurname(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void surnameNameInvalidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setSurname("Freeman");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("Di Caprio");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setSurname(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGSURN_ANS)));
	}

	@Test
	public void givennameNameValidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setGivenName("Alice");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("Alice");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setGivenName(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void givennameNameInvalidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setGivenName("Alice");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("Bob");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setGivenName(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGGIVEN_ANS)));
	}

	@Test
	public void commonnameNameValidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setCommonName("TestName");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("TestName");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setCommonName(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void commonnameNameInvalidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setCommonName("TestName");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("ProdName");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setCommonName(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGCOMMONN_ANS)));
	}

	@Test
	public void pseudonymNameValidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setPseudonym("Pseudonym");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("Pseudonym");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setPseudonym(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void pseudonymNameInvalidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setPseudonym("Pseudonym");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("Anonymous");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setPseudonym(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGPSEUDO_ANS)));
	}

	@Test
	public void titleNameValidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setTitle("CEO");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("CEO");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setTitle(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void titleNameInvalidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setTitle("CEO");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("CFO");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setTitle(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGTITLE_ANS)));
	}

	@Test
	public void emailNameValidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setEmail("valid@email.com");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("valid@email.com");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setEmail(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void emailNameInvalidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setEmail("invalid@email.com");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("valid@email.com");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setEmail(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGEMAIL_ANS)));
	}
	
	@Test
	public void countryNameValidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("LU");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setCountry(multiValuesConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void countryNameInvalidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("FR");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setCountry(multiValuesConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGCOUN_ANS)));
	}

	@Test
	public void localityNameValidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setLocality("Kehlen");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("Kehlen");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setLocality(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void localityNameInvalidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setLocality("Kehlen");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("Strassen");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setLocality(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGLOC_ANS)));
	}

	@Test
	public void stateNameValidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setState("Kehlen");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("Kehlen");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setState(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void stateNameInvalidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setState("Kehlen");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("Strassen");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setState(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGST_ANS)));
	}

	@Test
	public void organizationIdentifierNameValidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setOrganizationIdentifier("1215452");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("1215452");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setOrganizationIdentifier(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void organizationIdentifierNameInvalidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setOrganizationIdentifier("1215452");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("5215351");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setOrganizationIdentifier(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGORGAI_ANS)));
	}

	@Test
	public void organizationUnitNameValidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setOrganizationalUnit("Org Unit 1");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("Org Unit 1");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setOrganizationUnit(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void organizationUnitNameInvalidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setOrganizationalUnit("Org Unit 1");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("Org Unit 2");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setOrganizationUnit(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGORGAU_ANS)));
	}

	@Test
	public void organizationNameValidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setOrganizationName("Nowina Solutions");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("Nowina Solutions");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setOrganizationName(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void organizationNameInvalidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate xmlCertificate = xmlSignature.getSigningCertificate().getCertificate();
		xmlCertificate.setOrganizationName("Nowina Solutions");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add("Oldwina Solutions");
		multiValuesConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setOrganizationName(multiValuesConstraint);

		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGORGAN_ANS)));
	}
	
	@Test
	public void noAIATest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);
		
		XmlSigningCertificate signingCertificate = diagnosticData.getSignatures().get(0).getSigningCertificate();
		CertificateWrapper certificateWrapper = new CertificateWrapper(signingCertificate.getCertificate());
		certificateWrapper.getCAIssuersAccessUrls().clear();

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);

		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setAuthorityInfoAccessPresent(levelConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.BBB_XCV_AIA_PRES_ANS)));
	}
	
	@Test
	public void digestMatcherCryptoTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);
		
		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		List<XmlDigestMatcher> digestMatchers = xmlSignature.getDigestMatchers();
		digestMatchers.get(1).setDigestMethod(DigestAlgorithm.SHA1);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		String tstId = detailedReport.getTimestampIds().get(0);
		assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(tstId));
		
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlSAV sav = signatureBBB.getSAV();
		assertEquals(1, sav.getConclusion().getErrors().size());

		XmlCryptographicValidation cryptographicValidation = sav.getCryptographicValidation();
		assertEquals(DigestAlgorithm.SHA1, DigestAlgorithm.forXML(cryptographicValidation.getAlgorithm().getUri()));
		
		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_SIGND_PRT)));
	}
	
	@Test
	public void tstDigestMatcherCryptoTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);
		
		XmlTimestamp xmlTimestamp = diagnosticData.getUsedTimestamps().get(0);
		List<XmlDigestMatcher> digestMatchers = xmlTimestamp.getDigestMatchers();
		digestMatchers.get(0).setDigestMethod(DigestAlgorithm.SHA1);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(xmlTimestamp.getId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getBasicTimestampValidationSubIndication(xmlTimestamp.getId()));
		
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
		XmlSAV sav = signatureBBB.getSAV();
		assertEquals(1, sav.getConclusion().getErrors().size());

		XmlCryptographicValidation cryptographicValidation = sav.getCryptographicValidation();
		assertEquals(DigestAlgorithm.SHA1, DigestAlgorithm.forXML(cryptographicValidation.getAlgorithm().getUri()));
		
		List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertFalse(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_MESS_IMP)));
	}
	
	@Test
	public void messageDigestWithSha1WithTstTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/message-digest-sha1-with-tst.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicBuildingBlocksIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getBasicBuildingBlocksSubIndication(detailedReport.getFirstSignatureId()));
		
		assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
	}
	
	@Test
	public void messageDigestWithSha1WithBrokenTstTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/message-digest-sha1-with-tst.xml"));
		assertNotNull(diagnosticData);
		
		XmlTimestamp xmlTimestamp = diagnosticData.getUsedTimestamps().get(0);
		xmlTimestamp.getBasicSignature().setSignatureIntact(false);
		xmlTimestamp.getBasicSignature().setSignatureValid(false);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicBuildingBlocksIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getBasicBuildingBlocksSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));
	}
	
	@Test
	public void signaturePolicyStoreTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_signature_policy_store.xml"));
		assertNotNull(diagnosticData);
		
		ValidationPolicy policy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = policy.getSignatureConstraints();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		signatureConstraints.setSignaturePolicyStorePresent(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(policy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicBuildingBlocksIndication(detailedReport.getFirstSignatureId()));
	}
	
	@Test
	public void signaturePolicyStoreNotFoundTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_signature_policy_store.xml"));
		assertNotNull(diagnosticData);
		
		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		xmlSignature.setSignaturePolicyStore(null);
		
		ValidationPolicy policy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = policy.getSignatureConstraints();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		signatureConstraints.setSignaturePolicyStorePresent(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(policy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		
		XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.INDETERMINATE, bbb.getConclusion().getIndication());
		assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, bbb.getConclusion().getSubIndication());
		
		XmlVCI vci = bbb.getVCI();
		assertEquals(Indication.INDETERMINATE, vci.getConclusion().getIndication());
		assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, vci.getConclusion().getSubIndication());
		
		boolean signaturePolicyStoreCheckExecuted = false;
		for (XmlConstraint constraint : vci.getConstraint()) {
			if (MessageTag.BBB_VCI_ISPSUPP.name().equals(constraint.getName().getKey())) {
				signaturePolicyStoreCheckExecuted = true;
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
			}
		}
		assertTrue(signaturePolicyStoreCheckExecuted);
	}

	@Test
	public void signaturePolicyNotIdentifierFailLevelTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_zero_hash_policy.xml"));
		assertNotNull(diagnosticData);

		XmlPolicy xmlPolicy = diagnosticData.getSignatures().get(0).getPolicy();
		xmlPolicy.setIdentified(false);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().setPolicyAvailable(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.BBB_VCI_ISPA_ANS)));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId())));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicBuildingBlocksIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, detailedReport.getBasicBuildingBlocksSubIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.INDETERMINATE, bbb.getConclusion().getIndication());
		assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, bbb.getConclusion().getSubIndication());

		XmlVCI vci = bbb.getVCI();
		assertEquals(Indication.INDETERMINATE, vci.getConclusion().getIndication());
		assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, vci.getConclusion().getSubIndication());

		boolean sigPolicyIdentifiedCheckExecuted = false;
		boolean zeroHashPolicyCheckExecuted = false;
		for (XmlConstraint constraint : vci.getConstraint()) {
			if (MessageTag.BBB_VCI_ISPA.name().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_VCI_ISPA_ANS.name(), constraint.getError().getKey());
				sigPolicyIdentifiedCheckExecuted = true;
			} else if (MessageTag.BBB_VCI_IZHSP.name().equals(constraint.getName().getKey())) {
				zeroHashPolicyCheckExecuted = true;
				assertEquals(XmlStatus.OK, constraint.getStatus());
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(sigPolicyIdentifiedCheckExecuted);
		assertFalse(zeroHashPolicyCheckExecuted);
	}

	@Test
	public void signaturePolicyNotIdentifierInformLevelTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_zero_hash_policy.xml"));
		assertNotNull(diagnosticData);

		XmlPolicy xmlPolicy = diagnosticData.getSignatures().get(0).getPolicy();
		xmlPolicy.setIdentified(false);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.INFORM);
		validationPolicy.getSignatureConstraints().setPolicyAvailable(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.BBB_VCI_ISPA_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicBuildingBlocksIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.PASSED, bbb.getConclusion().getIndication());

		XmlVCI vci = bbb.getVCI();
		assertEquals(Indication.PASSED, vci.getConclusion().getIndication());

		boolean sigPolicyIdentifiedCheckExecuted = false;
		boolean zeroHashPolicyCheckExecuted = false;
		for (XmlConstraint constraint : vci.getConstraint()) {
			if (MessageTag.BBB_VCI_ISPA.name().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
				assertEquals(MessageTag.BBB_VCI_ISPA_ANS.name(), constraint.getInfo().getKey());
				sigPolicyIdentifiedCheckExecuted = true;
			} else if (MessageTag.BBB_VCI_IZHSP.name().equals(constraint.getName().getKey())) {
				zeroHashPolicyCheckExecuted = true;
				assertEquals(XmlStatus.OK, constraint.getStatus());
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(sigPolicyIdentifiedCheckExecuted);
		assertFalse(zeroHashPolicyCheckExecuted);
	}
	
	@Test
	public void zeroHashPolicyCheckTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_zero_hash_policy.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicBuildingBlocksIndication(detailedReport.getFirstSignatureId()));
		
		XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.PASSED, bbb.getConclusion().getIndication());
		
		XmlVCI vci = bbb.getVCI();
		assertEquals(Indication.PASSED, vci.getConclusion().getIndication());

		boolean sigPolicyIdentifiedCheckExecuted = false;
		boolean zeroHashPolicyCheckExecuted = false;
		for (XmlConstraint constraint : vci.getConstraint()) {
			if (MessageTag.BBB_VCI_ISPA.name().equals(constraint.getName().getKey())) {
				sigPolicyIdentifiedCheckExecuted = true;
			} else if (MessageTag.BBB_VCI_IZHSP.name().equals(constraint.getName().getKey())) {
				zeroHashPolicyCheckExecuted = true;
			}
			assertEquals(XmlStatus.OK, constraint.getStatus());
		}
		assertTrue(sigPolicyIdentifiedCheckExecuted);
		assertTrue(zeroHashPolicyCheckExecuted);
	}

	@Test
	public void referenceDuplicateTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/diag_data_xsw_attack.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlFC fc = bbb.getFC();
		assertNotNull(fc);

		boolean referenceDuplicationCheckExecuted = false;
		for (XmlConstraint constraint : fc.getConstraint()) {
			if (MessageTag.BBB_FC_ISRIA.name().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_FC_ISRIA_ANS.name(), constraint.getError().getKey());
				assertTrue(Utils.isStringNotBlank(constraint.getAdditionalInfo()));
				referenceDuplicationCheckExecuted = true;
			}
		}
		assertTrue(referenceDuplicationCheckExecuted);
	}

	@Test
	public void selfIssuedOcspWarnTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/diag_data_self_issued_ocsp.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		RevocationConstraints revocationConstraints = validationPolicy.getRevocationConstraints();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		revocationConstraints.setSelfIssuedOCSP(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_REVOC_SELF_ISSUED_OCSP_ANS)));
	}

	@Test
	public void selfIssuedOcspFailTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/diag_data_self_issued_ocsp.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		RevocationConstraints revocationConstraints = validationPolicy.getRevocationConstraints();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		revocationConstraints.setSelfIssuedOCSP(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_REVOC_SELF_ISSUED_OCSP_ANS)));
	}

	@Test
	public void selfIssuedCaOcspWarnTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/diag_data_self_issued_ca_ocsp.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		RevocationConstraints revocationConstraints = validationPolicy.getRevocationConstraints();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		revocationConstraints.setSelfIssuedOCSP(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_REVOC_SELF_ISSUED_OCSP_ANS)));
	}

	@Test
	public void selfIssuedWithOcspLoopTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/diag_data_with_ocsp_loop.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		RevocationConstraints revocationConstraints = validationPolicy.getRevocationConstraints();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		revocationConstraints.setSelfIssuedOCSP(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_REVOC_SELF_ISSUED_OCSP_ANS)));
	}

	@Test
	public void padesDoubleLtaTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/diag_data_pades_double_lta.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		executor.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);
		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(diagnosticData.getValidationDate(),
				simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

		executor.setValidationLevel(ValidationLevel.LONG_TERM_DATA);
		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(diagnosticData.getUsedTimestamps().get(1).getProductionTime(),
				simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

		executor.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(diagnosticData.getUsedTimestamps().get(0).getProductionTime(),
				simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void padesDocSigTstTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/diag_data_pades_doc_sig_tst.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		executor.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);
		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(diagnosticData.getValidationDate(),
				simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

		executor.setValidationLevel(ValidationLevel.LONG_TERM_DATA);
		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(diagnosticData.getUsedTimestamps().get(0).getProductionTime(),
				simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

		executor.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(diagnosticData.getUsedTimestamps().get(0).getProductionTime(),
				simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void padesDocMissingRevocDataTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/diag_data_pades_doc_sig_tst.xml"));
		assertNotNull(diagnosticData);

		// remove revocations
		diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate().getRevocations().clear();

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		executor.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);
		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(diagnosticData.getValidationDate(),
				simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

		// best-signature-time is not calculated as basic signature validation fails
		executor.setValidationLevel(ValidationLevel.LONG_TERM_DATA);
		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(diagnosticData.getValidationDate(),
				simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

		executor.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(diagnosticData.getValidationDate(),
				simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void grantedTspTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-qualification/granted-tsp.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();

		boolean certTypeCheckProcessed = false;
		for (XmlConstraint constraint : validationSignQual.getConstraint()) {
			if (MessageTag.QUAL_CERT_TYPE_AT_ST.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				certTypeCheckProcessed = true;
			}
		}
		assertTrue(certTypeCheckProcessed);
	}

	@Test
	public void grantedTspWithQualifierTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-qualification/granted-tsp-with-qualifier.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
		assertNotNull(validationSignQual);

		assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
		for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
			boolean consistencyCheckProcessed = false;
			for (XmlConstraint constraint : certQualification.getConstraint()) {
				if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					consistencyCheckProcessed = true;
				}
			}
			assertTrue(consistencyCheckProcessed);
		}
	}

	@Test
	public void grantedTspWithUnknownQualifierTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-qualification/granted-tsp-with-unknown-qualifier.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_TL_SERV_CONS_ANS3C)));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
		assertNotNull(validationSignQual);

		assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
		for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
			boolean consistencyCheckProcessed = false;
			for (XmlConstraint constraint : certQualification.getConstraint()) {
				if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.WARNING, constraint.getStatus());
					assertEquals(MessageTag.QUAL_TL_SERV_CONS_ANS3C.getId(), constraint.getWarning().getKey());
					consistencyCheckProcessed = true;
				}
			}
			assertTrue(consistencyCheckProcessed);
		}
	}

	@Test
	public void grantedTspQscdOverruleTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-qualification/granted-tsp-qscd-overrule.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
		assertNotNull(validationSignQual);

		assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
		for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
			boolean consistencyCheckProcessed = false;
			boolean qscdConsistencyCheckProcessed = false;
			for (XmlConstraint constraint : certQualification.getConstraint()) {
				if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					consistencyCheckProcessed = true;
				} else if (MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					qscdConsistencyCheckProcessed = true;
				}
			}
			assertTrue(consistencyCheckProcessed);
			assertTrue(qscdConsistencyCheckProcessed);
		}
	}

	@Test
	public void grantedTspSscdOverruleTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-qualification/granted-tsp-sscd-overrule.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS)));
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_QSCD_AT_ST_ANS, MessageTag.VT_CERTIFICATE_ISSUANCE_TIME)));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_QSCD_AT_ST_ANS, MessageTag.VT_BEST_SIGNATURE_TIME)));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_TL_SERV_CONS_ANS3B)));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
		assertNotNull(validationSignQual);

		assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
		for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
			boolean consistencyCheckProcessed = false;
			boolean qscdConsistencyCheckProcessed = false;
			for (XmlConstraint constraint : certQualification.getConstraint()) {
				if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.WARNING, constraint.getStatus());
					assertEquals(MessageTag.QUAL_TL_SERV_CONS_ANS3B.getId(), constraint.getWarning().getKey());
					consistencyCheckProcessed = true;
				} else if (MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
					assertEquals(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS.getId(), constraint.getError().getKey());
					qscdConsistencyCheckProcessed = true;
				}
			}
			assertTrue(consistencyCheckProcessed);
			assertTrue(qscdConsistencyCheckProcessed);
		}
	}

	@Test
	public void grantedTspSscdAndQscdOverruleTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-qualification/granted-tsp-sscd-and-qscd-overrule.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
		assertNotNull(validationSignQual);

		assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
		for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
			boolean consistencyCheckProcessed = false;
			boolean qscdConsistencyCheckProcessed = false;
			for (XmlConstraint constraint : certQualification.getConstraint()) {
				if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					consistencyCheckProcessed = true;
				} else if (MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					qscdConsistencyCheckProcessed = true;
				}
			}
			assertTrue(consistencyCheckProcessed);
			assertTrue(qscdConsistencyCheckProcessed);
		}
	}

	@Test
	public void qscdWithNoSscdOverruleTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-qualification/qscd-with-no-sscd-overrule.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS)));
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_QSCD_AT_ST_ANS, MessageTag.VT_BEST_SIGNATURE_TIME)));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_TL_SERV_CONS_ANS3B)));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
		assertNotNull(validationSignQual);

		assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
		for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
			boolean consistencyCheckProcessed = false;
			boolean qscdConsistencyCheckProcessed = false;
			for (XmlConstraint constraint : certQualification.getConstraint()) {
				if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.WARNING, constraint.getStatus());
					assertEquals(MessageTag.QUAL_TL_SERV_CONS_ANS3B.getId(), constraint.getWarning().getKey());
					consistencyCheckProcessed = true;
				} else if (MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
					assertEquals(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS.getId(), constraint.getError().getKey());
					qscdConsistencyCheckProcessed = true;
				}
			}
			assertTrue(consistencyCheckProcessed);
			assertTrue(qscdConsistencyCheckProcessed);
		}
	}

	@Test
	public void qscdWithQscdOverruleConflictTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-qualification/granted-tsp-qscd-overrule-conflict.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS)));
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_QSCD_AT_ST_ANS, MessageTag.VT_BEST_SIGNATURE_TIME)));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_TL_SERV_CONS_ANS3)));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
		assertNotNull(validationSignQual);

		assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
		for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
			boolean consistencyCheckProcessed = false;
			boolean qscdConsistencyCheckProcessed = false;
			for (XmlConstraint constraint : certQualification.getConstraint()) {
				if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.WARNING, constraint.getStatus());
					assertEquals(MessageTag.QUAL_TL_SERV_CONS_ANS3.getId(), constraint.getWarning().getKey());
					consistencyCheckProcessed = true;
				} else if (MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
					assertEquals(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS.getId(), constraint.getError().getKey());
					qscdConsistencyCheckProcessed = true;
				}
			}
			assertTrue(consistencyCheckProcessed);
			assertTrue(qscdConsistencyCheckProcessed);
		}
	}

	@Test
	public void qscdWithManagedOnBehalfAndQscdOverruleConflictTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-qualification/granted-tsp-managedonbehalf-and-qscd-overrule-conflict.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertFalse(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
		assertNotNull(validationSignQual);

		assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
		for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
			boolean consistencyCheckProcessed = false;
			boolean qscdConsistencyCheckProcessed = false;
			for (XmlConstraint constraint : certQualification.getConstraint()) {
				if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					consistencyCheckProcessed = true;
				} else if (MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					qscdConsistencyCheckProcessed = true;
				}
			}
			assertTrue(consistencyCheckProcessed);
			assertTrue(qscdConsistencyCheckProcessed);
		}
	}


	@Test
	public void qscdWithManagedOnBehalfAndNoQscdOverruleConflictTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-qualification/granted-tsp-managedonbehalf-and-noqscd-overrule-conflict.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS)));
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_QSCD_AT_ST_ANS, MessageTag.VT_BEST_SIGNATURE_TIME)));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_TL_SERV_CONS_ANS3)));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
		assertNotNull(validationSignQual);

		assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
		for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
			boolean consistencyCheckProcessed = false;
			boolean qscdConsistencyCheckProcessed = false;
			for (XmlConstraint constraint : certQualification.getConstraint()) {
				if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.WARNING, constraint.getStatus());
					assertEquals(MessageTag.QUAL_TL_SERV_CONS_ANS3.getId(), constraint.getWarning().getKey());
					consistencyCheckProcessed = true;
				} else if (MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
					assertEquals(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS.getId(), constraint.getError().getKey());
					qscdConsistencyCheckProcessed = true;
				}
			}
			assertTrue(consistencyCheckProcessed);
			assertTrue(qscdConsistencyCheckProcessed);
		}
	}


	@Test
	public void qscdWithStatusAsInCertAndQscdOverruleConflictTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-qualification/granted-tsp-statusasincert-and-qscd-overrule-conflict.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS)));
		assertTrue(Utils.isCollectionNotEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_QSCD_AT_ST_ANS, MessageTag.VT_BEST_SIGNATURE_TIME)));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.QUAL_TL_SERV_CONS_ANS3A)));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();
		assertNotNull(validationSignQual);

		assertEquals(2, validationSignQual.getValidationCertificateQualification().size());
		for (XmlValidationCertificateQualification certQualification : validationSignQual.getValidationCertificateQualification()) {
			boolean consistencyCheckProcessed = false;
			boolean qscdConsistencyCheckProcessed = false;
			for (XmlConstraint constraint : certQualification.getConstraint()) {
				if (MessageTag.QUAL_TL_SERV_CONS.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.WARNING, constraint.getStatus());
					assertEquals(MessageTag.QUAL_TL_SERV_CONS_ANS3A.getId(), constraint.getWarning().getKey());
					consistencyCheckProcessed = true;
				} else if (MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
					assertEquals(MessageTag.QUAL_HAS_CONSISTENT_BY_QSCD_ANS.getId(), constraint.getError().getKey());
					qscdConsistencyCheckProcessed = true;
				}
			}
			assertTrue(consistencyCheckProcessed);
			assertTrue(qscdConsistencyCheckProcessed);
		}
	}

	@Test
	public void withdrawnAtTOIAndGrantedAtTOSTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-qualification/withdrawn-at-toi-granted-at-tos.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void grantedAtTOIAndWithdrawnAtTOSTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-qualification/granted-at-toi-withdrawn-at-tos.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void esigAtTOIAndEsealAtTOSTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-qualification/esig-at-toi-eseal-at-tos.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.UNKNOWN_QC_QSCD, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignQual = xmlSignature.getValidationSignatureQualification();

		boolean certTypeCheckProcessed = false;
		for (XmlConstraint constraint : validationSignQual.getConstraint()) {
			if (MessageTag.QUAL_CERT_TYPE_AT_ST.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.QUAL_CERT_TYPE_AT_ST_ANS.getId(), constraint.getWarning().getKey());
				certTypeCheckProcessed = true;
			}
		}
		assertTrue(certTypeCheckProcessed);
	}

	@Test
	public void noQscdAtTOIAndQscdAtTOSTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-qualification/noqscd-at-toi-qscd-at-tos.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void qscdAtTOIAndNoQscdAtTOSTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sig-qualification/qscd-at-toi-noqscd-at-tos.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void oneFailedRacTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data-one-failed-revocation.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlConclusion conclusion = bbb.getConclusion();
		assertEquals(Indication.INDETERMINATE, conclusion.getIndication());
		assertTrue(Utils.isCollectionNotEmpty(conclusion.getErrors()));
		assertFalse(checkMessageValuePresence(convert(conclusion.getErrors()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDC_ANS)));
		assertFalse(checkMessageValuePresence(convert(conclusion.getWarnings()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDC_ANS)));

		boolean failedRacFound = false;
		XmlXCV xcv = bbb.getXCV();
		for (XmlRAC rac : xcv.getSubXCV().get(0).getCRS().getRAC()) {
			if (Indication.INDETERMINATE.equals(rac.getConclusion().getIndication())) {
				assertFalse(failedRacFound);
				assertTrue(checkMessageValuePresence(convert(rac.getConclusion().getErrors()),
						i18nProvider.getMessage(MessageTag.BBB_XCV_IRDC_ANS)));
				failedRacFound = true;
			}
		}
		assertTrue(failedRacFound);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDC_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDC_ANS)));

	}

	@Test
	public void failedRacTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data-failed-revocation.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		List<XmlRevocation> usedRevocations = diagnosticData.getUsedRevocations();

		Reports reports = executor.execute();

		DetailedReport detailedReport = reports.getDetailedReport();
		for (XmlRevocation xmlRevocation : usedRevocations) {
			assertEquals(Indication.INDETERMINATE, detailedReport.getBasicBuildingBlocksIndication(xmlRevocation.getId()));
			assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicBuildingBlocksSubIndication(xmlRevocation.getId()));
			assertEquals(2, detailedReport.getAdESValidationErrors(xmlRevocation.getId()).size());
			assertEquals(0, detailedReport.getAdESValidationWarnings(xmlRevocation.getId()).size());
			assertEquals(0, detailedReport.getAdESValidationInfos(xmlRevocation.getId()).size());

			XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(xmlRevocation.getId());
			assertEquals(2, bbb.getConclusion().getErrors().size());
			assertEquals(0, bbb.getConclusion().getWarnings().size());
			assertEquals(0, bbb.getConclusion().getInfos().size());

			XmlXCV xcv = bbb.getXCV();
			assertNotNull(xcv);
			assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
			assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, xcv.getConclusion().getSubIndication());
			assertEquals(2, xcv.getConclusion().getErrors().size());
			assertEquals(0, xcv.getConclusion().getWarnings().size());
			assertEquals(0, xcv.getConclusion().getInfos().size());

			boolean failedSubXCVFound = false;
			for (XmlSubXCV subXCV : xcv.getSubXCV()){
				if (Indication.INDETERMINATE.equals(subXCV.getConclusion().getIndication())) {
					assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, subXCV.getConclusion().getSubIndication());
					assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()),
							i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
					assertFalse(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()),
							i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));
					failedSubXCVFound = true;
				}
			}
			assertTrue(failedSubXCVFound);

			assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()),
					i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
			assertFalse(checkMessageValuePresence(convert(xcv.getConclusion().getWarnings()),
					i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

			assertTrue(checkMessageValuePresence(detailedReport.getAdESValidationErrors(xmlRevocation.getId()),
					i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
			assertFalse(checkMessageValuePresence(detailedReport.getAdESValidationWarnings(xmlRevocation.getId()),
					i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));
		}

		assertEquals(Indication.TOTAL_PASSED, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));
		assertFalse(checkMessageValuePresence(detailedReport.getAdESValidationErrors(detailedReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
		assertFalse(checkMessageValuePresence(detailedReport.getAdESValidationWarnings(detailedReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

		XmlConstraintsConclusion highestConclusion = detailedReport.getHighestConclusion(detailedReport.getFirstSignatureId());
		assertFalse(checkMessageValuePresence(convert(highestConclusion.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.ARCH_LTVV_ANS)));
		assertFalse(checkMessageValuePresence(convert(highestConclusion.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
		assertFalse(checkMessageValuePresence(convert(highestConclusion.getConclusion().getWarnings()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

		SimpleReport simpleReport = reports.getSimpleReport();
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.ARCH_LTVV_ANS)));

	}

	@Test
	public void counterSignatureReplaceAttackTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_counter_sig_replace_attack.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		Set<SignatureWrapper> counterSignatures = diagnosticData.getAllCounterSignatures();
		assertEquals(1, counterSignatures.size());

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(counterSignatures.iterator().next().getId());
		assertNotNull(bbb);
		assertEquals(Indication.FAILED, bbb.getConclusion().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, bbb.getConclusion().getSubIndication());

		XmlCV cv = bbb.getCV();
		assertEquals(Indication.FAILED, cv.getConclusion().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, cv.getConclusion().getSubIndication());

		boolean signatureValueCheckPresentFound = false;
		boolean signatureValueCheckIntactFound = false;
		for (XmlConstraint constraint : cv.getConstraint()) {
			if (MessageTag.BBB_CV_CS_CSSVF.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				signatureValueCheckPresentFound = true;
			} else if (MessageTag.BBB_CV_CS_CSPS.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertNotNull(constraint.getError());
				assertEquals(MessageTag.BBB_CV_CS_CSPS_ANS.getId(), constraint.getError().getKey());
				signatureValueCheckIntactFound = true;
			}
		}
		assertTrue(signatureValueCheckPresentFound);
		assertTrue(signatureValueCheckIntactFound);
	}

	@Test
	public void expiredOCSPResponderTest() throws Exception {
		// see DSS-2338
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_expired_ocsp_responder.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		assertNotNull(signingCertificate);

		List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
		assertEquals(1, certificateRevocationData.size());
		CertificateRevocationWrapper revocationWrapper = certificateRevocationData.get(0);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(3, subXCVs.size());

		XmlSubXCV subXCV = subXCVs.get(0);
		assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

		boolean acceptableRevocationCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getError().getKey());
				acceptableRevocationCheckFound = true;
			}
		}
		assertTrue(acceptableRevocationCheckFound);

		List<XmlRAC> rac = subXCV.getCRS().getRAC();
		assertEquals(1, rac.size());

		XmlRAC xmlRAC = rac.get(0);
		assertEquals(Indication.INDETERMINATE, xmlRAC.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlRAC.getConclusion().getSubIndication());

		boolean consistencyCheckFound = false;
		for (XmlConstraint constraint : xmlRAC.getConstraint()) {
			if (MessageTag.BBB_XCV_IRDC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_IRDC_ANS.getId(), constraint.getError().getKey());
				assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_PRODUCED_AT_OUT_OF_BOUNDS,
								ValidationProcessUtils.getFormattedDate(revocationWrapper.getProductionDate()),
								ValidationProcessUtils.getFormattedDate(revocationWrapper.getSigningCertificate().getNotBefore()),
								ValidationProcessUtils.getFormattedDate(revocationWrapper.getSigningCertificate().getNotAfter())),
						constraint.getAdditionalInfo());
				consistencyCheckFound = true;
			}
		}
		assertTrue(consistencyCheckFound);
	}

	@Test
	public void expiredOCSPResponderWithInformLevelTest() throws Exception {
		// see DSS-2338
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_expired_ocsp_responder.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
		BasicSignatureConstraints basicSignatureConstraints = signatureConstraints.getBasicSignatureConstraints();
		CertificateConstraints signingCertificateConstraints = basicSignatureConstraints.getSigningCertificate();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.INFORM);
		signingCertificateConstraints.setAcceptableRevocationDataFound(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		assertNotNull(signingCertificate);

		List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
		assertEquals(1, certificateRevocationData.size());
		CertificateRevocationWrapper revocationWrapper = certificateRevocationData.get(0);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(3, subXCVs.size());

		XmlSubXCV subXCV = subXCVs.get(0);
		assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

		boolean acceptableRevocationCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getInfo().getKey());
				acceptableRevocationCheckFound = true;
			}
		}
		assertTrue(acceptableRevocationCheckFound);

		List<XmlRAC> rac = subXCV.getCRS().getRAC();
		assertEquals(1, rac.size());

		XmlRAC xmlRAC = rac.get(0);
		assertEquals(Indication.INDETERMINATE, xmlRAC.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlRAC.getConclusion().getSubIndication());

		boolean consistencyCheckFound = false;
		for (XmlConstraint constraint : xmlRAC.getConstraint()) {
			if (MessageTag.BBB_XCV_IRDC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_IRDC_ANS.getId(), constraint.getError().getKey());
				assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_PRODUCED_AT_OUT_OF_BOUNDS,
						ValidationProcessUtils.getFormattedDate(revocationWrapper.getProductionDate()),
						ValidationProcessUtils.getFormattedDate(revocationWrapper.getSigningCertificate().getNotBefore()),
						ValidationProcessUtils.getFormattedDate(revocationWrapper.getSigningCertificate().getNotAfter())),
						constraint.getAdditionalInfo());
				consistencyCheckFound = true;
			}
		}
		assertTrue(consistencyCheckFound);
	}

	@Test
	public void skipRevocationCheckTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_expired_ocsp_responder.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
		BasicSignatureConstraints basicSignatureConstraints = signatureConstraints.getBasicSignatureConstraints();
		CertificateConstraints signingCertificateConstraints = basicSignatureConstraints.getSigningCertificate();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.INFORM);
		signingCertificateConstraints.setAcceptableRevocationDataFound(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());
		executor.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(3, subXCVs.size());

		XmlSubXCV subXCV = subXCVs.get(0);
		assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getInfos()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));
	}

	@Test
	public void notYetValidCRLIssuerTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_not_yet_valid_ca.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		RevocationConstraints revocationConstraints = validationPolicy.getRevocationConstraints();
		BasicSignatureConstraints basicSignatureConstraints = revocationConstraints.getBasicSignatureConstraints();
		CertificateConstraints signingCertificateConstraints = basicSignatureConstraints.getSigningCertificate();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.INFORM);
		signingCertificateConstraints.setAcceptableRevocationDataFound(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		assertNotNull(signingCertificate);

		List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
		assertEquals(1, certificateRevocationData.size());

		CertificateWrapper caCertificate = signingCertificate.getSigningCertificate();
		assertNotNull(caCertificate);

		certificateRevocationData = caCertificate.getCertificateRevocationData();
		assertEquals(1, certificateRevocationData.size());
		CertificateRevocationWrapper revocationWrapper = certificateRevocationData.get(0);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(3, subXCVs.size());

		XmlSubXCV subXCV = subXCVs.get(0);
		assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
		assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, subXCV.getConclusion().getSubIndication());

		subXCV = subXCVs.get(1);
		assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

		List<XmlRAC> rac = subXCV.getCRS().getRAC();
		assertEquals(1, rac.size());

		XmlRAC xmlRAC = rac.get(0);
		assertEquals(Indication.INDETERMINATE, xmlRAC.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlRAC.getConclusion().getSubIndication());

		boolean consistencyCheckFound = false;
		for (XmlConstraint constraint : xmlRAC.getConstraint()) {
			if (MessageTag.BBB_XCV_IRDC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_IRDC_ANS.getId(), constraint.getError().getKey());
				assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_THIS_UPDATE_BEFORE,
						ValidationProcessUtils.getFormattedDate(revocationWrapper.getThisUpdate()),
						ValidationProcessUtils.getFormattedDate(caCertificate.getNotBefore()),
						ValidationProcessUtils.getFormattedDate(caCertificate.getNotAfter())),
						constraint.getAdditionalInfo());
				consistencyCheckFound = true;
			}
		}
		assertTrue(consistencyCheckFound);
	}

	@Test
	public void brokenRevocationDataTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_with_broken_revocation.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(3, subXCVs.size());

		XmlSubXCV subXCV = subXCVs.get(0);
		assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());
		assertEquals(2, subXCV.getConclusion().getErrors().size());
		assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));
		assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

		XmlCRS crs = subXCV.getCRS();
		assertNotNull(crs);
		assertEquals(Indication.INDETERMINATE, crs.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, crs.getConclusion().getSubIndication());
		assertEquals(2, crs.getConclusion().getErrors().size());
		assertTrue(checkMessageValuePresence(convert(crs.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

		List<XmlRAC> racs = crs.getRAC();
		assertEquals(1, racs.size());

		XmlRAC rac = racs.get(0);
		assertEquals(Indication.FAILED, rac.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CRYPTO_FAILURE, rac.getConclusion().getSubIndication());
		assertEquals(1, rac.getConclusion().getErrors().size());
		assertTrue(checkMessageValuePresence(convert(rac.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));
	}

	@Test
	public void brokenRevocationDataWithWarnSigIntactTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_with_broken_revocation.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		RevocationConstraints revocationConstraints = validationPolicy.getRevocationConstraints();
		BasicSignatureConstraints basicSignatureConstraints = revocationConstraints.getBasicSignatureConstraints();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		basicSignatureConstraints.setSignatureIntact(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(3, subXCVs.size());

		XmlSubXCV subXCV = subXCVs.get(0);
		assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());
		assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()),
				i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));

		List<XmlRAC> racs = subXCV.getCRS().getRAC();
		assertEquals(1, racs.size());

		XmlRAC rac = racs.get(0);
		assertEquals(Indication.PASSED, rac.getConclusion().getIndication());
		assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()),
				i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));
	}

	@Test
	public void certificatePolicyIdsTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlCertificatePolicies xmlCertificatePolicies = new XmlCertificatePolicies();
		xmlCertificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
		XmlCertificatePolicy oid = new XmlCertificatePolicy();
		oid.setValue("1.3.76.38.1.1.2");
		xmlCertificatePolicies.getCertificatePolicy().add(oid);
		signingCertificate.getCertificateExtensions().add(xmlCertificatePolicies);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("1.3.76.38.1.1.1");
		certificateConstraints.setPolicyIds(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCIPI_ANS)));

		// should be able to process
		oid.setValue(null);

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCIPI_ANS)));

		oid.setValue("");

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCIPI_ANS)));

		oid.setValue(" ");

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCIPI_ANS)));

		oid.setValue("1.3.76.38.1.1.1");

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void certificatePolicyQualifiedIdsTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();

		XmlCertificatePolicies xmlCertificatePolicies = new XmlCertificatePolicies();
		xmlCertificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
		XmlCertificatePolicy oid = new XmlCertificatePolicy();
		oid.setValue(CertificatePolicy.NCPP.getOid());
		xmlCertificatePolicies.getCertificatePolicy().add(oid);
		signingCertificate.getCertificateExtensions().add(xmlCertificatePolicies);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		certificateConstraints.setPolicyQualificationIds(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCIQC_ANS)));

		oid.setValue(CertificatePolicy.QCP_PUBLIC.getOid());

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void certificatePolicySupportedByQSCDIdsTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlCertificatePolicies xmlCertificatePolicies = new XmlCertificatePolicies();
		xmlCertificatePolicies.setOID(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
		XmlCertificatePolicy oid = new XmlCertificatePolicy();
		oid.setValue(CertificatePolicy.NCPP.getOid());
		xmlCertificatePolicies.getCertificatePolicy().add(oid);
		signingCertificate.getCertificateExtensions().add(xmlCertificatePolicies);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		certificateConstraints.setPolicySupportedByQSCDIds(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCIQSCD_ANS)));

		oid.setValue(CertificatePolicy.QCP_PUBLIC_WITH_SSCD.getOid());

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void qcComplianceTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		certificateConstraints.setQcCompliance(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCC_ANS)));

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		XmlQcCompliance xmlQcCompliance = new XmlQcCompliance();
		xmlQcCompliance.setPresent(true);
		xmlQcStatements.setQcCompliance(xmlQcCompliance);
		signingCertificate.getCertificateExtensions().add(xmlQcStatements);

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void qcEuLimitValueCurrencyTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		XmlQcEuLimitValue xmlQcEuLimitValue = new XmlQcEuLimitValue();
		xmlQcEuLimitValue.setCurrency("AUD");
		xmlQcStatements.setQcEuLimitValue(xmlQcEuLimitValue);
		signingCertificate.getCertificateExtensions().add(xmlQcStatements);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		ValueConstraint constraint = new ValueConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.setValue("EUR");
		certificateConstraints.setQcEuLimitValueCurrency(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCLVHAC_ANS)));

		xmlQcEuLimitValue.setCurrency("EUR");

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void minQcEuLimitValueTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		XmlQcEuLimitValue xmlQCLimitValue = new XmlQcEuLimitValue();
		xmlQCLimitValue.setAmount(1000);
		xmlQCLimitValue.setExponent(0);
		xmlQcStatements.setQcEuLimitValue(xmlQCLimitValue);
		signingCertificate.getCertificateExtensions().add(xmlQcStatements);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		IntValueConstraint constraint = new IntValueConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.setValue(500000);
		certificateConstraints.setMinQcEuLimitValue(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCLVA_ANS)));

		xmlQCLimitValue.setExponent(3);

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void minQcEuRetentionPeriodTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		xmlQcStatements.setQcEuRetentionPeriod(3);
		signingCertificate.getCertificateExtensions().add(xmlQcStatements);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		IntValueConstraint constraint = new IntValueConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.setValue(5);
		certificateConstraints.setMinQcEuRetentionPeriod(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCERPA_ANS)));

		xmlQcStatements.setQcEuRetentionPeriod(10);

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void qcSSCDTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		XmlQcSSCD xmlQcSSCD = new XmlQcSSCD();
		xmlQcSSCD.setPresent(false);
		xmlQcStatements.setQcSSCD(xmlQcSSCD);
		signingCertificate.getCertificateExtensions().add(xmlQcStatements);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		certificateConstraints.setQcSSCD(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICSQCSSCD_ANS)));

		xmlQcSSCD.setPresent(true);

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void qcEuPDSLocationTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		XmlLangAndValue langAndValue = new XmlLangAndValue();
		langAndValue.setLang("en");
		langAndValue.setValue("https://repository.eid.lux.lu");
		xmlQcStatements.getQcEuPDS().add(langAndValue);
		signingCertificate.getCertificateExtensions().add(xmlQcStatements);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("https://repository.eid.belgium.be");
		certificateConstraints.setQcEuPDSLocation(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCPDSLA_ANS)));

		langAndValue.setValue("https://repository.eid.belgium.be");

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void qcTypeTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		XmlOID xmlOID = new XmlOID();
		xmlOID.setValue("0.4.0.1862.1.6.2");
		xmlOID.setDescription("qc-type-eseal");
		xmlQcStatements.setQcTypes(Arrays.asList(xmlOID));
		signingCertificate.getCertificateExtensions().add(xmlQcStatements);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("qc-type-esign");
		certificateConstraints.setQcType(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCTA_ANS)));

		xmlOID.setValue("0.4.0.1862.1.6.1");
		xmlOID.setDescription("qc-type-esign");

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void qcCCLegislationTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		signingCertificate.getCertificateExtensions().add(xmlQcStatements);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		// Id list empty (EU certificate expected)
		certificateConstraints.setQcLegislationCountryCodes(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		xmlQcStatements.setQcCClegislation(Arrays.asList("FR"));

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCDCQCCLCEC_ANS_EU)));

		constraint.getId().add("LU");

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCDCQCCLCEC_ANS)));

		constraint.getId().add("FR");

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void semanticsIdentifierForLegalPersonTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		XmlOID xmlOID = new XmlOID();
		xmlOID.setDescription("Semantics identifier for natural person");
		xmlOID.setValue("0.4.0.194121.1.1");
		xmlQcStatements.setSemanticsIdentifier(xmlOID);
		signingCertificate.getCertificateExtensions().add(xmlQcStatements);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.getId().add("0.4.0.194121.1.2");
		constraint.setLevel(Level.FAIL);
		certificateConstraints.setSemanticsIdentifier(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCSCSIA_ANS)));

		xmlOID.setDescription("Semantics identifier for legal person");
		xmlOID.setValue("0.4.0.194121.1.2");

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void semanticsIdentifierForNaturalPersonTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		XmlOID xmlOID = new XmlOID();
		xmlOID.setDescription("Semantics identifier for legal person");
		xmlOID.setValue("0.4.0.194121.1.2");
		xmlQcStatements.setSemanticsIdentifier(xmlOID);
		signingCertificate.getCertificateExtensions().add(xmlQcStatements);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.getId().add("0.4.0.194121.1.1");
		constraint.getId().add("0.4.0.194121.1.3");
		constraint.setLevel(Level.FAIL);
		certificateConstraints.setSemanticsIdentifier(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCSCSIA_ANS)));

		xmlOID.setDescription("Semantics identifier for natural person");
		xmlOID.setValue("0.4.0.194121.1.1");

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void semanticsIdentifierForEIDASLegalPersonTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		XmlOID xmlOID = new XmlOID();
		xmlOID.setDescription("Semantics identifier for eIDAS natural person");
		xmlOID.setValue("0.4.0.194121.1.3");
		xmlQcStatements.setSemanticsIdentifier(xmlOID);
		signingCertificate.getCertificateExtensions().add(xmlQcStatements);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.getId().add("0.4.0.194121.1.2");
		constraint.getId().add("0.4.0.194121.1.4");
		constraint.setLevel(Level.FAIL);
		certificateConstraints.setSemanticsIdentifier(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCSCSIA_ANS)));

		xmlOID.setDescription("Semantics identifier for eIDAS legal person");
		xmlOID.setValue("0.4.0.194121.1.4");

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void semanticsIdentifierForEIDASNaturalPersonTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		XmlOID xmlOID = new XmlOID();
		xmlOID.setDescription("Semantics identifier for eIDAS legal person");
		xmlOID.setValue("0.4.0.194121.1.4");
		xmlQcStatements.setSemanticsIdentifier(xmlOID);
		signingCertificate.getCertificateExtensions().add(xmlQcStatements);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.getId().add("0.4.0.194121.1.3");
		constraint.setLevel(Level.FAIL);
		certificateConstraints.setSemanticsIdentifier(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCSCSIA_ANS)));

		xmlOID.setDescription("Semantics identifier for eIDAS natural person");
		xmlOID.setValue("0.4.0.194121.1.3");

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void ps2dQcRolesOfPSPTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		XmlPSD2QcInfo xmlPSD2Info = new XmlPSD2QcInfo();
		XmlRoleOfPSP roleOfPSP = new XmlRoleOfPSP();
		XmlOID xmlOID = new XmlOID();
		xmlOID.setDescription("psp-as");
		xmlOID.setValue("0.4.0.19495.1.1");
		roleOfPSP.setOid(xmlOID);
		xmlPSD2Info.getRolesOfPSP().add(roleOfPSP);
		xmlQcStatements.setPSD2QcInfo(xmlPSD2Info);
		signingCertificate.getCertificateExtensions().add(xmlQcStatements);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("psp-pi");
		certificateConstraints.setPSD2QcTypeRolesOfPSP(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCRA_ANS)));

		xmlOID.setDescription("psp-pi");
		xmlOID.setValue("0.4.0.19495.1.2");

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void ps2dQcCANameTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		XmlPSD2QcInfo xmlPSD2Info = new XmlPSD2QcInfo();
		xmlPSD2Info.setNcaName("NBB");
		xmlQcStatements.setPSD2QcInfo(xmlPSD2Info);
		signingCertificate.getCertificateExtensions().add(xmlQcStatements);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("CSSF");
		certificateConstraints.setPSD2QcCompetentAuthorityName(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCNA_ANS)));

		xmlPSD2Info.setNcaName("CSSF");

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void ps2dQcCAIdTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate signingCertificate = xmlDiagnosticData.getSignatures().get(0)
				.getSigningCertificate().getCertificate();
		XmlQcStatements xmlQcStatements = new XmlQcStatements();
		xmlQcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
		XmlPSD2QcInfo xmlPSD2Info = new XmlPSD2QcInfo();
		xmlPSD2Info.setNcaId("BE-NBB");
		xmlQcStatements.setPSD2QcInfo(xmlPSD2Info);
		signingCertificate.getCertificateExtensions().add(xmlQcStatements);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints certificateConstraints = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("LU-CSSF");
		certificateConstraints.setPSD2QcCompetentAuthorityId(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CMDCICQCIA_ANS)));

		xmlPSD2Info.setNcaId("LU-CSSF");

		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void nextUpdateCheckTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		BasicSignatureConstraints basicSigConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();
		basicSigConstraints.getSigningCertificate().setOCSPNextUpdatePresent(null);
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		basicSigConstraints.getCACertificate().setCRLNextUpdatePresent(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlXCV xcv = sigBBB.getXCV();
		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(3, subXCVs.size());

		boolean signCertFound = false;
		boolean caCertFound = false;
		boolean rootCertFound = false;
		for (XmlSubXCV subXCV : subXCVs) {
			XmlRFC rfc = subXCV.getRFC();
			if (rfc != null) {
				RevocationWrapper revocation = diagnosticData.getRevocationById(rfc.getId());
				assertNotNull(revocation);
				if (RevocationType.OCSP.equals(revocation.getRevocationType())) {
					signCertFound = true;

					boolean nextUpdateCheckPerformed = false;
					List<XmlConstraint> constraints = rfc.getConstraint();
					for (XmlConstraint constraint : constraints) {
						if (MessageTag.BBB_RFC_NUP.getId().equals(constraint.getName().getKey())) {
							nextUpdateCheckPerformed = true;
							break;
						}
					}
					assertFalse(nextUpdateCheckPerformed);

				} else if (RevocationType.CRL.equals(revocation.getRevocationType())) {
					caCertFound = true;

					boolean nextUpdateCheckPerformed = false;
					List<XmlConstraint> constraints = rfc.getConstraint();
					for (XmlConstraint constraint : constraints) {
						if (MessageTag.BBB_RFC_NUP.getId().equals(constraint.getName().getKey())) {
							nextUpdateCheckPerformed = true;
							assertEquals(XmlStatus.OK, constraint.getStatus());
						}
					}
					assertTrue(nextUpdateCheckPerformed);
				}
			} else {
				rootCertFound = true;
			}
		}
		assertTrue(signCertFound);
		assertTrue(caCertFound);
		assertTrue(rootCertFound);
	}

	@Test
	public void nextUpdateCheckOCSPFailTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		BasicSignatureConstraints basicSigConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		basicSigConstraints.getSigningCertificate().setOCSPNextUpdatePresent(levelConstraint);
		basicSigConstraints.getCACertificate().setCRLNextUpdatePresent(null);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlXCV xcv = sigBBB.getXCV();
		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(3, subXCVs.size());

		boolean signCertFound = false;
		boolean caCertFound = false;
		boolean rootCertFound = false;
		for (XmlSubXCV subXCV : subXCVs) {
			XmlRFC rfc = subXCV.getRFC();
			if (rfc != null) {
				RevocationWrapper revocation = diagnosticData.getRevocationById(rfc.getId());
				assertNotNull(revocation);
				if (RevocationType.OCSP.equals(revocation.getRevocationType())) {
					signCertFound = true;

					boolean nextUpdateCheckPerformed = false;
					List<XmlConstraint> constraints = rfc.getConstraint();
					for (XmlConstraint constraint : constraints) {
						if (MessageTag.BBB_RFC_NUP.getId().equals(constraint.getName().getKey())) {
							nextUpdateCheckPerformed = true;
							assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
							assertEquals(MessageTag.BBB_RFC_NUP_ANS.getId(), constraint.getError().getKey());
						}
					}
					assertTrue(nextUpdateCheckPerformed);

				} else if (RevocationType.CRL.equals(revocation.getRevocationType())) {
					caCertFound = true;

					boolean nextUpdateCheckPerformed = false;
					List<XmlConstraint> constraints = rfc.getConstraint();
					for (XmlConstraint constraint : constraints) {
						if (MessageTag.BBB_RFC_NUP.getId().equals(constraint.getName().getKey())) {
							nextUpdateCheckPerformed = true;
							assertEquals(XmlStatus.OK, constraint.getStatus());
						}
					}
					assertFalse(nextUpdateCheckPerformed);
				}
			} else {
				rootCertFound = true;
			}
		}
		assertTrue(signCertFound);
		assertTrue(caCertFound);
		assertTrue(rootCertFound);
	}

	@Test
	public void signatureWithFailedContentTstTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/sig-with-content-tst.xml"));
		assertNotNull(xmlDiagnosticData);

		xmlDiagnosticData.getUsedTimestamps().get(0).getDigestMatchers().get(0).setDataIntact(false);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> timestamps = detailedReport.getSignatures().get(0).getTimestamps();
		assertEquals(1, timestamps.size());

		XmlValidationProcessBasicTimestamp validationProcessTimestamp = timestamps.get(0).getValidationProcessBasicTimestamp();
		assertEquals(Indication.FAILED, validationProcessTimestamp.getConclusion().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, validationProcessTimestamp.getConclusion().getSubIndication());
	}

	@Test
	public void signatureWithFailedContentTstFailSAVTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/sig-with-content-tst.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlTimestamp xmlContentTimestamp = xmlDiagnosticData.getUsedTimestamps().get(0);
		xmlContentTimestamp.getDigestMatchers().get(0).setDataIntact(false);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getSignedAttributes().setContentTimeStampMessageImprint(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_SAV_DMICTSTMCMI_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

		XmlSAV sav = signatureBBB.getSAV();
		assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

		boolean contentTstMessageImprintCheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			if (MessageTag.BBB_SAV_DMICTSTMCMI.getId().equals(constraint.getName().getKey())) {
				assertEquals(xmlContentTimestamp.getId(), constraint.getId());
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_SAV_DMICTSTMCMI_ANS.getId(), constraint.getError().getKey());
				contentTstMessageImprintCheckFound = true;
			}
		}
		assertTrue(contentTstMessageImprintCheckFound);
	}

	@Test
	public void validBLevelBestSignatureTimeTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data-lta.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlTimestamp signatureTst = xmlDiagnosticData.getUsedTimestamps().get(0);
		XmlTimestamp arcTst = xmlDiagnosticData.getUsedTimestamps().get(1);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(signatureTst.getProductionTime(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
		assertNotEquals(arcTst.getProductionTime(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
		assertNotEquals(xmlDiagnosticData.getValidationDate(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void validBLevelBrokenSigTstBestSignatureTimeTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data-lta.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlTimestamp signatureTst = xmlDiagnosticData.getUsedTimestamps().get(0);
		XmlTimestamp arcTst = xmlDiagnosticData.getUsedTimestamps().get(1);

		signatureTst.getBasicSignature().setSignatureIntact(false);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertNotEquals(signatureTst.getProductionTime(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
		assertEquals(arcTst.getProductionTime(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
		assertNotEquals(xmlDiagnosticData.getValidationDate(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void validBLevelTwoBrokenTstsBestSignatureTimeTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data-lta.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlTimestamp signatureTst = xmlDiagnosticData.getUsedTimestamps().get(0);
		XmlTimestamp arcTst = xmlDiagnosticData.getUsedTimestamps().get(1);

		signatureTst.getBasicSignature().setSignatureIntact(false);
		arcTst.getBasicSignature().setSignatureIntact(false);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertNotEquals(signatureTst.getProductionTime(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
		assertNotEquals(arcTst.getProductionTime(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
		assertEquals(xmlDiagnosticData.getValidationDate(), simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void multipleBBBErrorMessagesTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);
		List<XmlChainItem> certificateChain = xmlSignature.getCertificateChain();
		for (XmlChainItem chainItem : certificateChain) {
			XmlCertificate certificate = chainItem.getCertificate();
			certificate.setTrusted(false);
			certificate.setSources(Arrays.asList(CertificateSourceType.OTHER));
		}
		xmlSignature.getBasicSignature().setSignatureIntact(false);
		XmlStructuralValidation xmlStructuralValidation = new XmlStructuralValidation();
		xmlStructuralValidation.setValid(false);
		xmlSignature.setStructuralValidation(xmlStructuralValidation);

		XmlTimestamp contentTst = xmlDiagnosticData.getUsedTimestamps().get(0);
		contentTst.getBasicSignature().setSignatureIntact(false);

		List<XmlRelatedCertificate> relatedCertificates = contentTst.getFoundCertificates().getRelatedCertificates();
		for (XmlRelatedCertificate certificate : relatedCertificates) {
			certificate.getCertificateRefs().clear();
		}

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();

		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CRYPTO_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CCCBB_SIG_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_SAV_ISSV_ANS)));

		eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp =
				simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0);

		assertEquals(Indication.FAILED, xmlTimestamp.getIndication());
		assertEquals(SubIndication.SIG_CRYPTO_FAILURE, xmlTimestamp.getSubIndication());
		assertTrue(checkMessageValuePresence(convertMessages(xmlTimestamp.getAdESValidationDetails().getError()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CCCBB_TSP_ANS)));
		assertTrue(checkMessageValuePresence(convertMessages(xmlTimestamp.getAdESValidationDetails().getError()),
				i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));
		assertTrue(checkMessageValuePresence(convertMessages(xmlTimestamp.getAdESValidationDetails().getWarning()),
				i18nProvider.getMessage(MessageTag.BBB_ICS_ISASCP_ANS)));
	}

	@Test
	public void tstInfoTsaFieldOrderDoesNotMatchTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/dss-2155.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		TimestampConstraints timestampConstraints = validationPolicy.getTimestampConstraints();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		timestampConstraints.setTSAGeneralNamePresent(levelConstraint);
		timestampConstraints.setTSAGeneralNameContentMatch(levelConstraint);
		timestampConstraints.setTSAGeneralNameOrderMatch(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();

		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps =
				simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		assertEquals(1, signatureTimestamps.size());

		eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp = signatureTimestamps.get(0);
		assertEquals(Indication.INDETERMINATE, timestamp.getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, timestamp.getSubIndication());
		assertTrue(Utils.isCollectionEmpty(timestamp.getAdESValidationDetails().getInfo()));
		assertTrue(Utils.isCollectionEmpty(timestamp.getAdESValidationDetails().getWarning()));
		assertEquals(1, timestamp.getAdESValidationDetails().getError().size());
		assertEquals(MessageTag.BBB_TAV_DTSAOM_ANS.getId(),
				timestamp.getAdESValidationDetails().getError().get(0).getKey());
	}

	@Test
	public void tstInfoTsaFieldValueDoesNotMatchFailLevelTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/dss-2155.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlTimestamp xmlTimestamp = xmlDiagnosticData.getUsedTimestamps().get(0);
		XmlTSAGeneralName tsaGeneralName = xmlTimestamp.getTSAGeneralName();
		tsaGeneralName.setContentMatch(false);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		TimestampConstraints timestampConstraints = validationPolicy.getTimestampConstraints();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		timestampConstraints.setTSAGeneralNamePresent(levelConstraint);
		timestampConstraints.setTSAGeneralNameContentMatch(levelConstraint);
		timestampConstraints.setTSAGeneralNameOrderMatch(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();

		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps =
				simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		assertEquals(1, signatureTimestamps.size());

		eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp = signatureTimestamps.get(0);
		assertEquals(Indication.INDETERMINATE, timestamp.getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, timestamp.getSubIndication());
		assertTrue(Utils.isCollectionEmpty(timestamp.getAdESValidationDetails().getInfo()));
		assertTrue(Utils.isCollectionEmpty(timestamp.getAdESValidationDetails().getWarning()));
		assertEquals(1, timestamp.getAdESValidationDetails().getError().size());
		assertEquals(MessageTag.BBB_TAV_DTSAVM_ANS.getId(),
				timestamp.getAdESValidationDetails().getError().get(0).getKey());
	}

	@Test
	public void tstInfoTsaFieldValueNotPresentFailLevelTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/dss-2155.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlTimestamp xmlTimestamp = xmlDiagnosticData.getUsedTimestamps().get(0);
		xmlTimestamp.setTSAGeneralName(null);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		TimestampConstraints timestampConstraints = validationPolicy.getTimestampConstraints();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		timestampConstraints.setTSAGeneralNamePresent(levelConstraint);
		timestampConstraints.setTSAGeneralNameContentMatch(levelConstraint);
		timestampConstraints.setTSAGeneralNameOrderMatch(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();

		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps =
				simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		assertEquals(1, signatureTimestamps.size());

		eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp = signatureTimestamps.get(0);
		assertEquals(Indication.INDETERMINATE, timestamp.getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, timestamp.getSubIndication());
		assertTrue(Utils.isCollectionEmpty(timestamp.getAdESValidationDetails().getInfo()));
		assertTrue(Utils.isCollectionEmpty(timestamp.getAdESValidationDetails().getWarning()));
		assertEquals(1, timestamp.getAdESValidationDetails().getError().size());
		assertEquals(MessageTag.BBB_TAV_ITSAP_ANS.getId(),
				timestamp.getAdESValidationDetails().getError().get(0).getKey());
	}

	@Test
	public void tstInfoTsaFieldValueNotPresentSkipTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/dss-2155.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlTimestamp xmlTimestamp = xmlDiagnosticData.getUsedTimestamps().get(0);
		xmlTimestamp.setTSAGeneralName(null);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		TimestampConstraints timestampConstraints = validationPolicy.getTimestampConstraints();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		timestampConstraints.setTSAGeneralNameContentMatch(levelConstraint);
		timestampConstraints.setTSAGeneralNameOrderMatch(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();

		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps =
				simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		assertEquals(1, signatureTimestamps.size());

		eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp = signatureTimestamps.get(0);
		assertEquals(Indication.INDETERMINATE, timestamp.getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, timestamp.getSubIndication());
	}

	@Test
	public void openDocumentCoverageTest() throws Exception {
		// see DSS-2448
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_open_document.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		ContainerConstraints containerConstraints = validationPolicy.getContainerConstraints();

		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.setLevel(Level.FAIL);
		multiValuesConstraint.getId().add("application/vnd.oasis.opendocument.text");
		containerConstraints.setAcceptableMimeTypeFileContent(multiValuesConstraint);

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		containerConstraints.setAllFilesSigned(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void pkcs7Test() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_pkcs7.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
		SignedAttributesConstraints signedAttributes = signatureConstraints.getSignedAttributes();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		signedAttributes.setSigningCertificatePresent(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
		assertEquals(1, simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()).size());
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_ICS_ISASCP_ANS)));
	}

	@Test
	public void certificateOnHoldWithTimestampBeforeSuspensionTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_cert_on_hold_with_tst_before.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlXCV xcv = signatureBBB.getXCV();
		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(2, subXCVs.size());

		XmlSubXCV subXCV = subXCVs.get(0);
		boolean onHoldCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_ISCOH.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_ISCOH_ANS.getId(), constraint.getError().getKey());
				onHoldCheckFound = true;
			}
		}
		assertTrue(onHoldCheckFound);

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
		assertEquals(Indication.PASSED, validationProcessLongTermData.getConclusion().getIndication());

		onHoldCheckFound = false;
		for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
			if (MessageTag.ADEST_ISTPTBST.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				onHoldCheckFound = true;
			}
		}
		assertTrue(onHoldCheckFound);
	}

	@Test
	public void certificateOnHoldWithTimestampAfterSuspensionTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_cert_on_hold_with_tst_after.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<Message> validationErrors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
		assertTrue(Utils.isCollectionNotEmpty(validationErrors));
		assertTrue(checkMessageValuePresence(validationErrors, i18nProvider.getMessage(MessageTag.BBB_XCV_ISCOH_ANS)));
		assertTrue(checkMessageValuePresence(validationErrors, i18nProvider.getMessage(MessageTag.ADEST_ISTPTBST_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlXCV xcv = signatureBBB.getXCV();
		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(2, subXCVs.size());

		XmlSubXCV subXCV = subXCVs.get(0);
		boolean onHoldCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_ISCOH.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_ISCOH_ANS.getId(), constraint.getError().getKey());
				onHoldCheckFound = true;
			}
		}
		assertTrue(onHoldCheckFound);

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
		assertEquals(Indication.INDETERMINATE, validationProcessLongTermData.getConclusion().getIndication());
		assertEquals(SubIndication.TRY_LATER, validationProcessLongTermData.getConclusion().getSubIndication());

		onHoldCheckFound = false;
		for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
			if (MessageTag.ADEST_ISTPTBST.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.ADEST_ISTPTBST_ANS.getId(), constraint.getError().getKey());
				onHoldCheckFound = true;
			}
		}
		assertTrue(onHoldCheckFound);
	}

	@Test
	public void multipleRevocationDataTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_multiple_revocation.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		DetailedReport detailedReport = reports.getDetailedReport();

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void multipleRevocationDataWithBrokenArcTstTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_multiple_revocation.xml"));
		assertNotNull(xmlDiagnosticData);

		List<XmlTimestamp> usedTimestamps = xmlDiagnosticData.getUsedTimestamps();
		usedTimestamps.get(1).getDigestMatchers().get(0).setDataIntact(false);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		DetailedReport detailedReport = reports.getDetailedReport();

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

		boolean revocationIssuerPOECheckFound = false;
		boolean usedRevocIssuerPOECheckFound = false;
		boolean failedRevocFound = false;
		boolean validRevocFound = false;

		boolean psvCrsCheckFound = false;

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());

		XmlPSV psv = signatureBBB.getPSV();
		assertNotNull(psv);
		for (XmlConstraint constraint : psv.getConstraint()) {
			if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				psvCrsCheckFound = true;

			} else if (MessageTag.PSV_DIURDSCHPVR.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertNull(constraint.getWarning());
				assertEquals(MessageTag.PSV_DIURDSCHPVR_ANS.getId(), constraint.getError().getKey());
				usedRevocIssuerPOECheckFound = true;
			}
		}

		XmlCRS psvcrs = signatureBBB.getPSVCRS();
		assertNotNull(psvcrs);
		for (XmlConstraint crsConstraint : psvcrs.getConstraint()) {
			if (MessageTag.PSV_IPCRIAIDBEDC.getId().equals(crsConstraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, crsConstraint.getStatus());
				assertEquals(MessageTag.PSV_IPCRIAIDBEDC_ANS.getId(), crsConstraint.getWarning().getKey());
				assertNull(crsConstraint.getError());
				revocationIssuerPOECheckFound = true;

			} else if (MessageTag.ADEST_RORPIIC.getId().equals(crsConstraint.getName().getKey())) {
				if (XmlStatus.WARNING.equals(crsConstraint.getStatus())) {
					failedRevocFound = true;
				} else if (XmlStatus.OK.equals(crsConstraint.getStatus())) {
					validRevocFound = true;
				}
			}
		}

		assertTrue(revocationIssuerPOECheckFound);
		assertTrue(usedRevocIssuerPOECheckFound);
		assertTrue(failedRevocFound);
		assertTrue(validRevocFound);
		assertTrue(psvCrsCheckFound);

		assertTrue(checkMessageValuePresence(convert(psvcrs.getConclusion().getWarnings()),
				i18nProvider.getMessage(MessageTag.ADEST_RORPIIC_ANS)));

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.PSV_IPCRIAIDBEDC)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.PSV_DIURDSCHPVR)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRCIRI_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.ADEST_RORPIIC_ANS)));
	}

	@Test
	public void multipleRevocationDataWithRevocationIssuerWarnTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_multiple_revocation.xml"));
		assertNotNull(xmlDiagnosticData);

		List<XmlTimestamp> usedTimestamps = xmlDiagnosticData.getUsedTimestamps();
		usedTimestamps.get(1).getDigestMatchers().get(0).setDataIntact(false);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setRevocationIssuerNotExpired(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		DetailedReport detailedReport = reports.getDetailedReport();

		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRCIRI_ANS)));
	}

	@Test
	public void ojWithExpiredTstRevocationTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/oj-diag-data-with-tsts.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> timestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		assertEquals(3, timestamps.size());

		for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp : timestamps) {
			assertEquals(Indication.PASSED, timestamp.getIndication());
			assertNull(timestamp.getAdESValidationDetails());
		}

		DetailedReport detailedReport = reports.getDetailedReport();

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> xmlTimestamps = xmlSignature.getTimestamps();

		int validationTimeFailedTimestampCounter = 0;
		int validationTimePassedTimestampCounter = 0;
		for (eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp timestamp : xmlTimestamps) {
			XmlValidationProcessBasicTimestamp validationProcessTimestamp = timestamp.getValidationProcessBasicTimestamp();
			if (Indication.INDETERMINATE.equals(validationProcessTimestamp.getConclusion().getIndication())) {
				assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessTimestamp.getConclusion().getSubIndication());
				assertTrue(checkMessageValuePresence(convert(validationProcessTimestamp.getConclusion().getErrors()),
						i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
				++validationTimeFailedTimestampCounter;
			} else if (Indication.PASSED.equals(validationProcessTimestamp.getConclusion().getIndication())) {
				++validationTimePassedTimestampCounter;
			}
		}
		assertEquals(2, validationTimeFailedTimestampCounter);
		assertEquals(1, validationTimePassedTimestampCounter);

	}

	@Test
	public void xadesAWithValidInvalidAndInconsistentRevocationDataTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_xades_a_with_two_revocation.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();

		boolean invalidRevocFound = false;
		boolean inconsistentRevocFound = false;
		boolean validRevocFound = false;

		List<XmlCRS> crss = validationProcessLongTermData.getCRS();
		assertEquals(1, crss.size());
		for (XmlConstraint constraint : crss.get(0).getConstraint()) {
			if (MessageTag.ADEST_RORPIIC.getId().equals(constraint.getName().getKey())) {
				if (XmlStatus.WARNING.equals(constraint.getStatus())) {
					invalidRevocFound = true;
				}
			} else if (MessageTag.BBB_XCV_RAC.getId().equals(constraint.getName().getKey())) {
				if (XmlStatus.WARNING.equals(constraint.getStatus())) {
					inconsistentRevocFound = true;
				} else if (XmlStatus.OK.equals(constraint.getStatus())) {
					validRevocFound = true;
				}
			}
		}

		assertTrue(invalidRevocFound);
		assertTrue(inconsistentRevocFound);
		assertTrue(validRevocFound);
	}

	@Test
	public void failedRacWithinRacTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_failed_rac_within_rac.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(2, subXCVs.size());

		XmlSubXCV xmlSubXCV = subXCVs.get(0);
		List<XmlRAC> racs = xmlSubXCV.getCRS().getRAC();
		assertEquals(4, racs.size());

		boolean validRacFound = false;
		boolean failedRacFound = false;
		boolean racWithAllFailedIssuerRacsFound = false;
		boolean racWithOneFailedIssuerRacFound = false;
		for (XmlRAC rac : racs) {
			if (Indication.PASSED.equals(rac.getConclusion().getIndication())) {
				int invalidRacCounter = 0;
				int validRacCounter = 0;
				if (rac.getCRS() != null) {
					for (XmlRAC subRac : rac.getCRS().getRAC()) {
						if (Indication.PASSED.equals(subRac.getConclusion().getIndication())) {
							++validRacCounter;
						} else {
							++invalidRacCounter;
						}
					}
				}
				if (validRacCounter == 0 && invalidRacCounter == 0) {
					validRacFound = true;
				}
				if (validRacCounter > 0 && invalidRacCounter > 0) {
					assertFalse(checkMessageValuePresence(convert(rac.getConclusion().getWarnings()),
							i18nProvider.getMessage(MessageTag.BBB_XCV_RAC_ANS)));

					racWithOneFailedIssuerRacFound = true;
				}

			} else if (Indication.INDETERMINATE.equals(rac.getConclusion().getIndication())) {
				int invalidRacCounter = 0;
				int validRacCounter = 0;
				if (rac.getCRS() != null) {
					for (XmlRAC subRac : rac.getCRS().getRAC()) {
						if (Indication.PASSED.equals(subRac.getConclusion().getIndication())) {
							++validRacCounter;
						} else {
							++invalidRacCounter;
						}
					}
				}
				if (invalidRacCounter != 0 && validRacCounter == 0) {
					assertTrue(checkMessageValuePresence(convert(rac.getConclusion().getWarnings()),
							i18nProvider.getMessage(MessageTag.BBB_XCV_RAC_ANS)));
					racWithAllFailedIssuerRacsFound = true;
				}

			} else if (Indication.FAILED.equals(rac.getConclusion().getIndication())) {
				int racCounter = 0;
				for (XmlConstraint constraint : rac.getConstraint()) {
					if (MessageTag.BBB_XCV_RAC.getId().equals(constraint.getName().getKey())) {
						++racCounter;
					}
				}
				if (racCounter == 0) {
					failedRacFound = true;
				}
			}
		}
		assertTrue(validRacFound);
		assertTrue(failedRacFound);
		assertTrue(racWithAllFailedIssuerRacsFound);
		assertTrue(racWithOneFailedIssuerRacFound);
	}

	@Test
	public void dsaWith2048KeySizeTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_dsa_signature.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();

		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void dsaWith1024KeySizeTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_dsa_signature.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);
		xmlSignature.getBasicSignature().setKeyLengthUsedToSignThisToken("1024");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();

		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_AKSNR,
						EncryptionAlgorithm.DSA.getName(), "1024", MessageTag.ACCM_POS_SIG_SIG)));
	}

	@Test
	public void docMDPTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_with_object_modifications.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);
		XmlPDFSignatureDictionary pdfSignatureDictionary = xmlSignature.getPDFRevision().getPDFSignatureDictionary();

		XmlDocMDP xmlDocMDP = new XmlDocMDP();
		xmlDocMDP.setPermissions(CertificationPermission.NO_CHANGE_PERMITTED);
		pdfSignatureDictionary.setDocMDP(xmlDocMDP);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setDocMDP(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();

		boolean certificationSigFound = false;
		boolean secondSigFound = false;
		for (String sigId : simpleReport.getSignatureIdList()) {
			if (Indication.TOTAL_FAILED.equals(simpleReport.getIndication(sigId))) {
				assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(sigId));
				assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
						i18nProvider.getMessage(MessageTag.BBB_FC_ISVADMDPD_ANS)));
				certificationSigFound = true;

			} else if (Indication.TOTAL_PASSED.equals(simpleReport.getIndication(sigId))) {
				secondSigFound = true;
			}

		}
		assertTrue(certificationSigFound);
		assertTrue(secondSigFound);
	}

	@Test
	public void fieldMDPTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_with_object_modifications.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);
		XmlPDFSignatureDictionary pdfSignatureDictionary = xmlSignature.getPDFRevision().getPDFSignatureDictionary();

		XmlPDFLockDictionary xmlPDFLockDictionary = new XmlPDFLockDictionary();
		xmlPDFLockDictionary.setAction(PdfLockAction.ALL);
		pdfSignatureDictionary.setFieldMDP(xmlPDFLockDictionary);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setFieldMDP(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();

		boolean certificationSigFound = false;
		boolean secondSigFound = false;
		for (String sigId : simpleReport.getSignatureIdList()) {
			if (Indication.TOTAL_FAILED.equals(simpleReport.getIndication(sigId))) {
				assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(sigId));
				assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
						i18nProvider.getMessage(MessageTag.BBB_FC_ISVAFMDPD_ANS)));
				certificationSigFound = true;

			} else if (Indication.TOTAL_PASSED.equals(simpleReport.getIndication(sigId))) {
				secondSigFound = true;
			}

		}
		assertTrue(certificationSigFound);
		assertTrue(secondSigFound);
	}

	@Test
	public void sigFieldLockTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_with_object_modifications.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);

		XmlPDFLockDictionary xmlPDFLockDictionary = new XmlPDFLockDictionary();
		xmlPDFLockDictionary.setAction(PdfLockAction.ALL);
		xmlPDFLockDictionary.setPermissions(CertificationPermission.NO_CHANGE_PERMITTED);
		xmlSignature.getPDFRevision().getFields().get(0).setSigFieldLock(xmlPDFLockDictionary);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setSigFieldLock(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();

		boolean certificationSigFound = false;
		boolean secondSigFound = false;
		for (String sigId : simpleReport.getSignatureIdList()) {
			if (Indication.TOTAL_FAILED.equals(simpleReport.getIndication(sigId))) {
				assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(sigId));
				assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
						i18nProvider.getMessage(MessageTag.BBB_FC_ISVASFLD_ANS)));
				certificationSigFound = true;

			} else if (Indication.TOTAL_PASSED.equals(simpleReport.getIndication(sigId))) {
				secondSigFound = true;
			}

		}
		assertTrue(certificationSigFound);
		assertTrue(secondSigFound);
	}

	@Test
	public void formFillChangesTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_with_object_modifications.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);

		XmlObjectModification objectModification = new XmlObjectModification();
		objectModification.setAction(PdfObjectModificationType.CREATION);

		xmlSignature.getPDFRevision().getModificationDetection()
				.getObjectModifications().getSignatureOrFormFill().add(objectModification);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setFormFillChanges(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();

		boolean certificationSigFound = false;
		boolean secondSigFound = false;
		for (String sigId : simpleReport.getSignatureIdList()) {
			if (Indication.TOTAL_FAILED.equals(simpleReport.getIndication(sigId))) {
				assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(sigId));
				assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
						i18nProvider.getMessage(MessageTag.BBB_FC_DSCNFFSM_ANS)));
				certificationSigFound = true;

			} else if (Indication.TOTAL_PASSED.equals(simpleReport.getIndication(sigId))) {
				secondSigFound = true;
			}

		}
		assertTrue(certificationSigFound);
		assertTrue(secondSigFound);
	}

	@Test
	public void annotationChangesTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_with_object_modifications.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);

		XmlObjectModification objectModification = new XmlObjectModification();
		objectModification.setAction(PdfObjectModificationType.CREATION);

		xmlSignature.getPDFRevision().getModificationDetection()
				.getObjectModifications().getAnnotationChanges().add(objectModification);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setAnnotationChanges(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();

		boolean certificationSigFound = false;
		boolean secondSigFound = false;
		for (String sigId : simpleReport.getSignatureIdList()) {
			if (Indication.TOTAL_FAILED.equals(simpleReport.getIndication(sigId))) {
				assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(sigId));
				assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
						i18nProvider.getMessage(MessageTag.BBB_FC_DSCNACMDM_ANS)));
				certificationSigFound = true;

			} else if (Indication.TOTAL_PASSED.equals(simpleReport.getIndication(sigId))) {
				secondSigFound = true;
			}

		}
		assertTrue(certificationSigFound);
		assertTrue(secondSigFound);
	}

	@Test
	public void undefinedChangesTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_with_object_modifications.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);

		XmlObjectModification undefinedChange = new XmlObjectModification();
		undefinedChange.setAction(PdfObjectModificationType.CREATION);

		xmlSignature.getPDFRevision().getModificationDetection()
				.getObjectModifications().getUndefined().add(undefinedChange);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setUndefinedChanges(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();

		boolean certificationSigFound = false;
		boolean secondSigFound = false;
		for (String sigId : simpleReport.getSignatureIdList()) {
			if (Indication.TOTAL_FAILED.equals(simpleReport.getIndication(sigId))) {
				assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(sigId));
				assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
						i18nProvider.getMessage(MessageTag.BBB_FC_DSCNUOM_ANS)));
				certificationSigFound = true;

			} else if (Indication.TOTAL_PASSED.equals(simpleReport.getIndication(sigId))) {
				secondSigFound = true;
			}

		}
		assertTrue(certificationSigFound);
		assertTrue(secondSigFound);
	}

	@Test
	public void undefinedChangesTimestampTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_pades_lta_mod_tst.xml"));
		assertNotNull(xmlDiagnosticData);
		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getTimestampConstraints().getBasicSignatureConstraints().setUndefinedChanges(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();

		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		assertEquals(2, signatureTimestamps.size());

		DetailedReport detailedReport = reports.getDetailedReport();

		boolean sigTstFound = false;
		boolean arcTstFound = false;
		for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp : signatureTimestamps) {
			if (Indication.PASSED.equals(detailedReport.getBasicTimestampValidationIndication(timestamp.getId()))) {
				XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestamp.getId());
				assertNotNull(tstBBB);
				assertNull(tstBBB.getFC());
				sigTstFound = true;

			} else if (Indication.FAILED.equals(detailedReport.getBasicTimestampValidationIndication(timestamp.getId()))) {
				assertEquals(SubIndication.FORMAT_FAILURE, detailedReport.getBasicTimestampValidationSubIndication(timestamp.getId()));

				XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestamp.getId());
				assertNotNull(tstBBB);

				XmlFC fc = tstBBB.getFC();
				assertNotNull(tstBBB.getFC());
				assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
				assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());

				boolean undefinedChangedCheckFound = false;
				for (XmlConstraint constraint : fc.getConstraint()) {
					if (MessageTag.BBB_FC_DSCNUOM.getId().equals(constraint.getName().getKey())) {
						assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
						assertEquals(MessageTag.BBB_FC_DSCNUOM_ANS.getId(), constraint.getError().getKey());
						undefinedChangedCheckFound = true;
					} else {
						assertEquals(XmlStatus.OK, constraint.getStatus());
					}
				}
				assertTrue(undefinedChangedCheckFound);
				arcTstFound = true;

			}
		}
		assertTrue(sigTstFound);
		assertTrue(arcTstFound);
	}

	@Test
	public void noUndefinedChangesTimestampTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_pades_lta_mod_tst.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlTimestamp xmlTimestamp = xmlDiagnosticData.getUsedTimestamps().get(1);

		xmlTimestamp.getPDFRevision().getModificationDetection().setObjectModifications(new XmlObjectModifications());

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getTimestampConstraints().getBasicSignatureConstraints().setUndefinedChanges(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();

		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		assertEquals(2, signatureTimestamps.size());

		DetailedReport detailedReport = reports.getDetailedReport();

		boolean sigTstFound = false;
		boolean arcTstFound = false;
		for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp : signatureTimestamps) {
			assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(timestamp.getId()));

			XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestamp.getId());
			if (tstBBB.getFC() == null) {
				sigTstFound = true;

			} else {
				XmlFC fc = tstBBB.getFC();
				assertNotNull(tstBBB.getFC());
				assertEquals(Indication.PASSED, fc.getConclusion().getIndication());

				boolean undefinedChangedCheckFound = false;
				for (XmlConstraint constraint : fc.getConstraint()) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					if (MessageTag.BBB_FC_DSCNUOM.getId().equals(constraint.getName().getKey())) {
						undefinedChangedCheckFound = true;
					}
				}
				assertTrue(undefinedChangedCheckFound);
				arcTstFound = true;

			}
		}
		assertTrue(sigTstFound);
		assertTrue(arcTstFound);
	}

	@Test
	public void signCertRefWithSHA1Test() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		List<XmlRelatedCertificate> relatedCertificates = xmlSignature.getFoundCertificates().getRelatedCertificates();
		for (XmlRelatedCertificate relatedCertificate : relatedCertificates) {
			List<XmlCertificateRef> certificateRefs = relatedCertificate.getCertificateRefs();
			for (XmlCertificateRef certificateRef : certificateRefs) {
				if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(certificateRef.getOrigin())) {
					certificateRef.getDigestAlgoAndValue().setDigestMethod(DigestAlgorithm.SHA1);
				}
			}
		}

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
		SignedAttributesConstraints signedAttributes = signatureConstraints.getSignedAttributes();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		signedAttributes.setSigningCertificateDigestAlgorithm(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1.getName(), MessageTag.ACCM_POS_SIG_CERT_REF)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));
		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));
		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlSAV sav = signatureBBB.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, sav.getConclusion().getSubIndication());

		boolean signRefDACheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			if (i18nProvider.getMessage(MessageTag.ACCM, MessageTag.ACCM_POS_SIG_CERT_REF).equals(constraint.getName().getValue())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.ASCCM_AR_ANS_ANR.getId(), constraint.getError().getKey());
				signRefDACheckFound = true;
			}
		}
		assertTrue(signRefDACheckFound);

		checkReports(reports);
	}

	@Test
	public void signCertRefWithSHA1WithPOETest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/universign.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = ValidationPolicyFacade.newFacade().getValidationPolicy(
				new File("src/test/resources/policy/all-constraint-specified-policy.xml"));
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
		SignedAttributesConstraints signedAttributes = signatureConstraints.getSignedAttributes();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		signedAttributes.setSigningCertificateDigestAlgorithm(levelConstraint);

		CertificateConstraints signingCertificate = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getCACertificate();
		CryptographicConstraint cryptographic = signingCertificate.getCryptographic();
		AlgoExpirationDate algoExpirationDate = cryptographic.getAlgoExpirationDate();
		for (Algo algo : algoExpirationDate.getAlgos()) {
			if (DigestAlgorithm.SHA1.getName().equals(algo.getValue())) {
				algo.setDate("2020-1-1");
			}
		}

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));
		assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlSAV sav = signatureBBB.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, sav.getConclusion().getSubIndication());

		boolean signRefDACheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			if (i18nProvider.getMessage(MessageTag.ACCM, MessageTag.ACCM_POS_SIG_CERT_REF).equals(constraint.getName().getValue())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.ASCCM_AR_ANS_ANR.getId(), constraint.getError().getKey());
				signRefDACheckFound = true;
			}
		}
		assertTrue(signRefDACheckFound);

		checkReports(reports);
	}

	@Test
	public void signCertRefWithSHA1AcceptSignCertPolicyTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/universign.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = ValidationPolicyFacade.newFacade().getValidationPolicy(
				new File("src/test/resources/policy/all-constraint-specified-policy.xml"));
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
		SignedAttributesConstraints signedAttributes = signatureConstraints.getSignedAttributes();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		signedAttributes.setSigningCertificateDigestAlgorithm(levelConstraint);

		CertificateConstraints signingCertificate = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		CryptographicConstraint cryptographic = signingCertificate.getCryptographic();
		AlgoExpirationDate algoExpirationDate = cryptographic.getAlgoExpirationDate();
		for (Algo algo : algoExpirationDate.getAlgos()) {
			if (DigestAlgorithm.SHA1.getName().equals(algo.getValue())) {
				algo.setDate("2020-1-1");
			}
		}

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

		checkReports(reports);
	}

	@Test
	public void signCertRefDigestCheckOnLTATest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/DSS-1453/diag-data-lta-dss.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
		SignedAttributesConstraints signedAttributes = signatureConstraints.getSignedAttributes();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		signedAttributes.setSigningCertificateDigestAlgorithm(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1.getName(), MessageTag.ACCM_POS_SIG_CERT_REF)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));
		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));
		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlSAV sav = signatureBBB.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, sav.getConclusion().getSubIndication());

		boolean signRefDACheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			if (i18nProvider.getMessage(MessageTag.ACCM, MessageTag.ACCM_POS_SIG_CERT_REF).equals(constraint.getName().getValue())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.ASCCM_AR_ANS_ANR.getId(), constraint.getError().getKey());
				signRefDACheckFound = true;
			}
		}
		assertTrue(signRefDACheckFound);

		checkReports(reports);
	}

	@Test
	public void thisUpdateBeforeBestSignatureTimeNoRevocationFreshnessCheckTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_thisUpdate_before_sigTst.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
		CertificateConstraints signingCertificate = signatureConstraints.getBasicSignatureConstraints().getSigningCertificate();
		TimeConstraint timeConstraint = new TimeConstraint();
		timeConstraint.setUnit(TimeUnit.SECONDS);
		timeConstraint.setValue(0);
		timeConstraint.setLevel(Level.IGNORE);
		signingCertificate.setRevocationFreshness(timeConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		checkReports(reports);
	}

	@Test
	public void thisUpdateBeforeBestSignatureTimeWithRevocationFreshnessCheckTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_thisUpdate_before_sigTst.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
		CertificateConstraints signingCertificate = signatureConstraints.getBasicSignatureConstraints().getSigningCertificate();
		TimeConstraint timeConstraint = new TimeConstraint();
		timeConstraint.setUnit(TimeUnit.SECONDS);
		timeConstraint.setValue(0);
		timeConstraint.setLevel(Level.FAIL);
		signingCertificate.setRevocationFreshness(timeConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_RFC_IRIF_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		List<XmlSubXCV> subXCV = xcv.getSubXCV();
		assertEquals(2, subXCV.size());

		XmlSubXCV xmlSubXCV = subXCV.get(0);
		assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
		assertEquals(SubIndication.TRY_LATER, xmlSubXCV.getConclusion().getSubIndication());

		XmlCRS crs = xmlSubXCV.getCRS();
		assertNotNull(crs);
		assertEquals(1, crs.getRAC().size());

		XmlRFC rfc = xmlSubXCV.getRFC();
		assertNotNull(rfc);
		assertEquals(Indication.INDETERMINATE, rfc.getConclusion().getIndication());
		assertEquals(SubIndication.TRY_LATER, rfc.getConclusion().getSubIndication());

		boolean revocationFreshCheckFound = false;
		for (XmlConstraint constraint : rfc.getConstraint()) {
			if (MessageTag.BBB_RFC_IRIF.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				revocationFreshCheckFound = true;
			}
		}
		assertTrue(revocationFreshCheckFound);

		checkReports(reports);
	}

	@Test
	public void oldAndFreshOCSPsRevocationFreshnessCheckTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_with_old_and_fresh_ocsp.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
		CertificateConstraints signingCertificate = signatureConstraints.getBasicSignatureConstraints().getSigningCertificate();
		TimeConstraint timeConstraint = new TimeConstraint();
		timeConstraint.setUnit(TimeUnit.SECONDS);
		timeConstraint.setValue(0);
		timeConstraint.setLevel(Level.FAIL);
		signingCertificate.setRevocationFreshness(timeConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		List<XmlSubXCV> subXCV = xcv.getSubXCV();
		assertEquals(2, subXCV.size());

		XmlSubXCV xmlSubXCV = subXCV.get(0);
		assertEquals(Indication.PASSED, xmlSubXCV.getConclusion().getIndication());

		XmlCRS crs = xmlSubXCV.getCRS();
		assertNotNull(crs);
		assertEquals(2, crs.getRAC().size());

		XmlRFC rfc = xmlSubXCV.getRFC();
		assertNotNull(rfc);
		assertEquals(Indication.PASSED, rfc.getConclusion().getIndication());

		boolean revocationFreshCheckFound = false;
		for (XmlConstraint constraint : rfc.getConstraint()) {
			if (MessageTag.BBB_RFC_IRIF.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				revocationFreshCheckFound = true;
			}
		}
		assertTrue(revocationFreshCheckFound);

		checkReports(reports);
	}

	@Test
	public void failTimestampDelayTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/universign.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		validationPolicy.getTimestampConstraints().getTimestampDelay().setLevel(Level.FAIL);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void signBeforeBestSignatureTimeTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_sign_before_sig_tst.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NOT_YET_VALID, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.TSV_IBSTAIDOSC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.FAILED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.NOT_YET_VALID, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
		assertNotNull(validationProcessLongTermData);

		boolean signTimeNotBeforeCertNotBeforeCheckFound = false;
		for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
			if (MessageTag.TSV_IBSTAIDOSC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.TSV_IBSTAIDOSC_ANS.getId(), constraint.getError().getKey());
				signTimeNotBeforeCertNotBeforeCheckFound = true;
			}
		}
		assertTrue(signTimeNotBeforeCertNotBeforeCheckFound);
	}

	@Test
	public void checkJAdESKidValidSigTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_jades_valid.xml"));
		assertNotNull(diagnosticData);

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignedAttributesConstraints signedAttributes = validationPolicy.getSignatureConstraints().getSignedAttributes();
		signedAttributes.setKeyIdentifierPresent(levelConstraint);
		signedAttributes.setKeyIdentifierMatch(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void checkJAdESNoKidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_jades_valid.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlFoundCertificates foundCertificates = xmlSignature.getFoundCertificates();
		for (XmlRelatedCertificate relatedCertificate : foundCertificates.getRelatedCertificates()) {
			Iterator<XmlCertificateRef> iterator = relatedCertificate.getCertificateRefs().iterator();
			while (iterator.hasNext()) {
				XmlCertificateRef certificateRef = iterator.next();
				if (CertificateRefOrigin.KEY_IDENTIFIER.equals(certificateRef.getOrigin())) {
					iterator.remove();
				}
			}
		}

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignedAttributesConstraints signedAttributes = validationPolicy.getSignatureConstraints().getSignedAttributes();
		signedAttributes.setKeyIdentifierPresent(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_ICS_ISAKIDP_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlSAV sav = signatureBBB.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

		boolean kidPresentCheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertNotNull(constraint.getError());
				assertEquals(MessageTag.BBB_ICS_ISAKIDP_ANS.getId(), constraint.getError().getKey());
				kidPresentCheckFound = true;
			}
		}
		assertTrue(kidPresentCheckFound);
	}

	@Test
	public void checkJAdESKidDoesNotMatchTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_jades_valid.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlFoundCertificates foundCertificates = xmlSignature.getFoundCertificates();
		for (XmlRelatedCertificate relatedCertificate : foundCertificates.getRelatedCertificates()) {
			Iterator<XmlCertificateRef> iterator = relatedCertificate.getCertificateRefs().iterator();
			while (iterator.hasNext()) {
				XmlCertificateRef certificateRef = iterator.next();
				if (CertificateRefOrigin.KEY_IDENTIFIER.equals(certificateRef.getOrigin())) {
					certificateRef.getIssuerSerial().setMatch(false);
				}
			}
		}

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignedAttributesConstraints signedAttributes = validationPolicy.getSignatureConstraints().getSignedAttributes();
		signedAttributes.setKeyIdentifierMatch(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_ICS_DKIDVM_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlSAV sav = signatureBBB.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

		boolean kidPresentCheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			if (MessageTag.BBB_ICS_DKIDVM.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertNotNull(constraint.getError());
				assertEquals(MessageTag.BBB_ICS_DKIDVM_ANS.getId(), constraint.getError().getKey());
				kidPresentCheckFound = true;
			}
		}
		assertTrue(kidPresentCheckFound);
	}

	@Test
	public void counterSignatureFailedFormatTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/counter-signature-valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		String counterSigId = null;
		for (XmlSignature xmlSignature : diagnosticData.getSignatures()) {
			if (xmlSignature.isCounterSignature() != null && xmlSignature.isCounterSignature()) {
				xmlSignature.setSignatureFormat(SignatureLevel.XML_NOT_ETSI);
				counterSigId = xmlSignature.getId();
			}
		}
		assertNotNull(counterSigId);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints counterSignatureConstraints = validationPolicy.getCounterSignatureConstraints();
		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.getId().add("XAdES-BASELINE-B");
		constraint.getId().add("XAdES-BASELINE-T");
		constraint.getId().add("XAdES-BASELINE-LT");
		constraint.getId().add("XAdES-BASELINE-LTA");
		constraint.setLevel(Level.FAIL);

		counterSignatureConstraints.setAcceptableFormats(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(counterSigId));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(counterSigId));

		checkReports(reports);
	}

	@Test
	public void counterSignatureNoPolicyPresentTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/counter-signature-valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		String counterSigId = null;
		for (XmlSignature xmlSignature : diagnosticData.getSignatures()) {
			if (xmlSignature.isCounterSignature() != null && xmlSignature.isCounterSignature()) {
				counterSigId = xmlSignature.getId();
			}
		}
		assertNotNull(counterSigId);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints counterSignatureConstraints = validationPolicy.getCounterSignatureConstraints();

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.getId().add("ANY_POLICY");
		constraint.setLevel(Level.FAIL);

		counterSignatureConstraints.setAcceptablePolicies(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(counterSigId));
		assertEquals(SubIndication.POLICY_PROCESSING_ERROR, simpleReport.getSubIndication(counterSigId));

		checkReports(reports);
	}

	@Test
	public void checkMinAndMaxUpdateValidLTTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_xades_level_lta_revo_freshness.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
		CertificateConstraints caCertificateConstraints = signatureConstraints
				.getBasicSignatureConstraints().getCACertificate();
		caCertificateConstraints.getRevocationFreshness().setLevel(Level.FAIL);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<XmlSignature> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		XmlSignature xmlSignature = signatures.get(0);
		XmlSigningCertificate signingCertificate = xmlSignature.getSigningCertificate();
		assertNotNull(signingCertificate);
		XmlSigningCertificate caCertificate = signingCertificate.getCertificate().getSigningCertificate();
		assertNotNull(caCertificate);
		List<XmlCertificateRevocation> revocations = caCertificate.getCertificate().getRevocations();
		assertEquals(1, revocations.size());

		assertEquals(revocations.get(0).getRevocation().getNextUpdate(),
				simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));

		List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
		assertEquals(1, usedTimestamps.size());
		XmlTimestamp xmlTimestamp = usedTimestamps.get(0);

		assertEquals(xmlTimestamp.getSigningCertificate().getCertificate().getNotAfter(),
				simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

		checkReports(reports);
	}

	@Test
	public void checkMinAndMaxUpdateValidTrustedCATest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_xades_level_lta_revo_freshness.xml"));
		assertNotNull(diagnosticData);

		List<XmlSignature> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		XmlSignature xmlSignature = signatures.get(0);
		XmlSigningCertificate signingCertificate = xmlSignature.getSigningCertificate();
		assertNotNull(signingCertificate);
		XmlSigningCertificate caCertificate = signingCertificate.getCertificate().getSigningCertificate();
		assertNotNull(caCertificate);

		caCertificate.getCertificate().setTrusted(true);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
		CertificateConstraints caCertificateConstraints = signatureConstraints
				.getBasicSignatureConstraints().getCACertificate();
		caCertificateConstraints.getRevocationFreshness().setLevel(Level.FAIL);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
		assertEquals(1, usedTimestamps.size());
		XmlTimestamp xmlTimestamp = usedTimestamps.get(0);
		XmlSigningCertificate signTstCertificate = xmlTimestamp.getSigningCertificate();
		assertNotNull(signTstCertificate);

		List<XmlCertificateRevocation> revocations = signTstCertificate.getCertificate().getRevocations();
		assertEquals(2, revocations.size());
		Date firstUpdateTime = null;
		for (XmlCertificateRevocation revocation : revocations) {
			if (firstUpdateTime == null || firstUpdateTime.after(revocation.getRevocation().getNextUpdate())) {
				firstUpdateTime = revocation.getRevocation().getNextUpdate();
			}
		}
		assertNotNull(firstUpdateTime);

		assertEquals(firstUpdateTime, simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));

		assertEquals(xmlTimestamp.getSigningCertificate().getCertificate().getNotAfter(),
				simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

		checkReports(reports);
	}

	@Test
	public void checkMinAndMaxUpdateValidTrustedCAAndTstIssuerTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_xades_level_lta_revo_freshness.xml"));
		assertNotNull(diagnosticData);

		List<XmlSignature> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		XmlSignature xmlSignature = signatures.get(0);
		XmlSigningCertificate signingCertificate = xmlSignature.getSigningCertificate();
		assertNotNull(signingCertificate);
		XmlSigningCertificate caCertificate = signingCertificate.getCertificate().getSigningCertificate();
		assertNotNull(caCertificate);

		caCertificate.getCertificate().setTrusted(true);

		List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
		assertEquals(1, usedTimestamps.size());
		XmlTimestamp xmlTimestamp = usedTimestamps.get(0);
		XmlSigningCertificate signTstCertificate = xmlTimestamp.getSigningCertificate();
		assertNotNull(signTstCertificate);

		signTstCertificate.getCertificate().setTrusted(true);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();

		List<XmlCertificateRevocation> revocations = signingCertificate.getCertificate().getRevocations();
		assertEquals(2, revocations.size());
		Date firstUpdateTime = null;
		for (XmlCertificateRevocation revocation : revocations) {
			if (firstUpdateTime == null || firstUpdateTime.after(revocation.getRevocation().getNextUpdate())) {
				firstUpdateTime = revocation.getRevocation().getNextUpdate();
			}
		}
		assertNotNull(firstUpdateTime);

		assertEquals(firstUpdateTime, simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));

		assertEquals(xmlTimestamp.getSigningCertificate().getCertificate().getNotAfter(),
				simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

		checkReports(reports);
	}

	@Test
	public void checkMinAndMaxNoTstTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_xades_level_lta_revo_freshness.xml"));
		assertNotNull(diagnosticData);

		diagnosticData.setUsedTimestamps(Collections.emptyList());

		List<XmlSignature> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		XmlSignature xmlSignature = signatures.get(0);

		xmlSignature.setFoundTimestamps(Collections.emptyList());

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		XmlSigningCertificate signingCertificate = xmlSignature.getSigningCertificate();
		assertNotNull(signingCertificate);
		XmlSigningCertificate caCertificate = signingCertificate.getCertificate().getSigningCertificate();
		assertNotNull(caCertificate);
		List<XmlCertificateRevocation> revocations = caCertificate.getCertificate().getRevocations();
		assertEquals(1, revocations.size());

		assertEquals(revocations.get(0).getRevocation().getNextUpdate(),
				simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));

		assertEquals(signingCertificate.getCertificate().getNotAfter(),
				simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

		checkReports(reports);
	}

	@Test
	public void checkMinAndMaxUpdateValidAtSignTimeTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_xades_level_lta_revo_freshness.xml"));
		assertNotNull(diagnosticData);

		List<XmlSignature> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		XmlSignature xmlSignature = signatures.get(0);
		XmlSigningCertificate signingCertificate = xmlSignature.getSigningCertificate();
		assertNotNull(signingCertificate);
		XmlSigningCertificate caCertificate = signingCertificate.getCertificate().getSigningCertificate();
		assertNotNull(caCertificate);

		List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
		assertEquals(1, usedTimestamps.size());
		XmlTimestamp xmlTimestamp = usedTimestamps.get(0);
		xmlTimestamp.setProductionTime(xmlSignature.getClaimedSigningTime());

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();

		List<XmlCertificateRevocation> revocations = caCertificate.getCertificate().getRevocations();
		assertEquals(1, revocations.size());

		assertEquals(revocations.get(0).getRevocation().getNextUpdate(),
				simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));

		assertEquals(xmlTimestamp.getSigningCertificate().getCertificate().getNotAfter(),
				simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

		checkReports(reports);
	}

	@Test
	public void checkMinAndMaxUpdateValidTrustedCATstAtSignTimeTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_xades_level_lta_revo_freshness.xml"));
		assertNotNull(diagnosticData);

		List<XmlSignature> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		XmlSignature xmlSignature = signatures.get(0);
		XmlSigningCertificate signingCertificate = xmlSignature.getSigningCertificate();
		assertNotNull(signingCertificate);
		XmlSigningCertificate caCertificate = signingCertificate.getCertificate().getSigningCertificate();
		assertNotNull(caCertificate);

		caCertificate.getCertificate().setTrusted(true);

		List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
		assertEquals(1, usedTimestamps.size());
		XmlTimestamp xmlTimestamp = usedTimestamps.get(0);
		xmlTimestamp.setProductionTime(xmlSignature.getClaimedSigningTime());

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();

		assertNull(simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));
		assertEquals(xmlTimestamp.getSigningCertificate().getCertificate().getNotAfter(),
				simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

		checkReports(reports);
	}

	@Test
	public void revocationFreshnessSigningCertificateTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
		CertificateConstraints signingCertificateConstraints = signatureConstraints
				.getBasicSignatureConstraints().getSigningCertificate();

		TimeConstraint constraint = new TimeConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.setUnit(TimeUnit.SECONDS);
		constraint.setValue(0);
		signingCertificateConstraints.setRevocationFreshness(constraint);

		signatureConstraints.getBasicSignatureConstraints().getCACertificate()
				.getRevocationFreshness().setLevel(Level.IGNORE);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_RFC_IRIF_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		XmlCertificate signingCertificate = diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
		String signingCertificateId = signingCertificate.getId();
		String caCertificateId = signingCertificate.getSigningCertificate().getCertificate().getId();

		boolean signingCertificateFound = false;
		boolean caCertificateFound = false;
		boolean rootCertificateFound = false;
		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(3, subXCVs.size());
		for (XmlSubXCV subXCV : subXCVs) {
			if (signingCertificateId.equals(subXCV.getId())) {
				XmlRFC rfc = subXCV.getRFC();
				assertNotNull(rfc);
				assertEquals(Indication.INDETERMINATE, rfc.getConclusion().getIndication());
				assertEquals(SubIndication.TRY_LATER, rfc.getConclusion().getSubIndication());

				boolean revocationFreshnessCheckFound = false;
				for (XmlConstraint xmlConstraint : rfc.getConstraint()) {
					if (MessageTag.BBB_RFC_IRIF.getId().equals(xmlConstraint.getName().getKey())) {
						assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
						assertEquals(MessageTag.BBB_RFC_IRIF_ANS.getId(), xmlConstraint.getError().getKey());
						revocationFreshnessCheckFound = true;
					}
				}
				assertTrue(revocationFreshnessCheckFound);

				signingCertificateFound = true;

			} else if (caCertificateId.equals(subXCV.getId())) {
				XmlRFC rfc = subXCV.getRFC();
				assertNotNull(rfc);
				assertEquals(Indication.PASSED, rfc.getConclusion().getIndication());

				boolean revocationFreshnessCheckFound = false;
				for (XmlConstraint xmlConstraint : rfc.getConstraint()) {
					if (MessageTag.BBB_RFC_IRIF.getId().equals(xmlConstraint.getName().getKey())) {
						assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
						revocationFreshnessCheckFound = true;
					}
				}
				assertTrue(revocationFreshnessCheckFound);
				caCertificateFound = true;

			} else {
				XmlRFC rfc = subXCV.getRFC();
				assertNull(rfc);

				rootCertificateFound = true;
			}
		}
		assertTrue(signingCertificateFound);
		assertTrue(caCertificateFound);
		assertTrue(rootCertificateFound);

		checkReports(reports);
	}

	@Test
	public void revocationFreshnessSigningCertificateWithTimeTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
		CertificateConstraints signingCertificateConstraints = signatureConstraints
				.getBasicSignatureConstraints().getSigningCertificate();

		TimeConstraint constraint = new TimeConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.setUnit(TimeUnit.HOURS);
		constraint.setValue(24);
		signingCertificateConstraints.setRevocationFreshness(constraint);

		signatureConstraints.getBasicSignatureConstraints().getCACertificate()
				.getRevocationFreshness().setLevel(Level.IGNORE);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		XmlCertificate signingCertificate = diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
		String signingCertificateId = signingCertificate.getId();
		String caCertificateId = signingCertificate.getSigningCertificate().getCertificate().getId();

		boolean signingCertificateFound = false;
		boolean caCertificateFound = false;
		boolean rootCertificateFound = false;
		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(3, subXCVs.size());
		for (XmlSubXCV subXCV : subXCVs) {
			if (signingCertificateId.equals(subXCV.getId())) {
				XmlRFC rfc = subXCV.getRFC();
				assertNotNull(rfc);
				assertEquals(Indication.PASSED, rfc.getConclusion().getIndication());

				boolean revocationFreshnessCheckFound = false;
				for (XmlConstraint xmlConstraint : rfc.getConstraint()) {
					if (MessageTag.BBB_RFC_IRIF.getId().equals(xmlConstraint.getName().getKey())) {
						assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
						revocationFreshnessCheckFound = true;
					}
				}
				assertTrue(revocationFreshnessCheckFound);

				signingCertificateFound = true;

			} else if (caCertificateId.equals(subXCV.getId())) {
				XmlRFC rfc = subXCV.getRFC();
				assertNotNull(rfc);
				assertEquals(Indication.PASSED, rfc.getConclusion().getIndication());

				boolean revocationFreshnessCheckFound = false;
				for (XmlConstraint xmlConstraint : rfc.getConstraint()) {
					if (MessageTag.BBB_RFC_IRIF.getId().equals(xmlConstraint.getName().getKey())) {
						assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
						revocationFreshnessCheckFound = true;
					}
				}
				assertTrue(revocationFreshnessCheckFound);
				caCertificateFound = true;

			} else {
				XmlRFC rfc = subXCV.getRFC();
				assertNull(rfc);

				rootCertificateFound = true;
			}
		}
		assertTrue(signingCertificateFound);
		assertTrue(caCertificateFound);
		assertTrue(rootCertificateFound);

		checkReports(reports);
	}

	@Test
	public void revocationFreshnessCACertificateTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();

		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate()
				.getRevocationFreshness().setLevel(Level.IGNORE);

		CertificateConstraints caCertificateConstraints = signatureConstraints
				.getBasicSignatureConstraints().getCACertificate();

		TimeConstraint constraint = new TimeConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.setUnit(TimeUnit.SECONDS);
		constraint.setValue(0);
		caCertificateConstraints.setRevocationFreshness(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_RFC_IRIF_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		XmlCertificate signingCertificate = diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
		String signingCertificateId = signingCertificate.getId();
		String caCertificateId = signingCertificate.getSigningCertificate().getCertificate().getId();

		boolean signingCertificateFound = false;
		boolean caCertificateFound = false;
		boolean rootCertificateFound = false;
		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(3, subXCVs.size());
		for (XmlSubXCV subXCV : subXCVs) {
			if (signingCertificateId.equals(subXCV.getId())) {
				XmlRFC rfc = subXCV.getRFC();
				assertNotNull(rfc);
				assertEquals(Indication.PASSED, rfc.getConclusion().getIndication());

				boolean revocationFreshnessCheckFound = false;
				for (XmlConstraint xmlConstraint : rfc.getConstraint()) {
					if (MessageTag.BBB_RFC_IRIF.getId().equals(xmlConstraint.getName().getKey())) {
						assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
						revocationFreshnessCheckFound = true;
					}
				}
				assertTrue(revocationFreshnessCheckFound);

				signingCertificateFound = true;

			} else if (caCertificateId.equals(subXCV.getId())) {
				XmlRFC rfc = subXCV.getRFC();
				assertNotNull(rfc);
				assertEquals(Indication.INDETERMINATE, rfc.getConclusion().getIndication());
				assertEquals(SubIndication.TRY_LATER, rfc.getConclusion().getSubIndication());

				boolean revocationFreshnessCheckFound = false;
				for (XmlConstraint xmlConstraint : rfc.getConstraint()) {
					if (MessageTag.BBB_RFC_IRIF.getId().equals(xmlConstraint.getName().getKey())) {
						assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
						assertEquals(MessageTag.BBB_RFC_IRIF_ANS.getId(), xmlConstraint.getError().getKey());
						revocationFreshnessCheckFound = true;
					}
				}
				assertTrue(revocationFreshnessCheckFound);

				caCertificateFound = true;

			} else {
				XmlRFC rfc = subXCV.getRFC();
				assertNull(rfc);

				rootCertificateFound = true;
			}
		}
		assertTrue(signingCertificateFound);
		assertTrue(caCertificateFound);
		assertTrue(rootCertificateFound);

		checkReports(reports);
	}

	@Test
	public void revocationFreshnessCACertificateNextUpdateCheckTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();

		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate()
				.getRevocationFreshness().setLevel(Level.IGNORE);

		CertificateConstraints caCertificateConstraints = signatureConstraints
				.getBasicSignatureConstraints().getCACertificate();
		caCertificateConstraints.setRevocationFreshness(null);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		caCertificateConstraints.setRevocationFreshnessNextUpdate(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		XmlCertificate signingCertificate = diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
		String signingCertificateId = signingCertificate.getId();
		String caCertificateId = signingCertificate.getSigningCertificate().getCertificate().getId();

		boolean signingCertificateFound = false;
		boolean caCertificateFound = false;
		boolean rootCertificateFound = false;
		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(3, subXCVs.size());
		for (XmlSubXCV subXCV : subXCVs) {
			if (signingCertificateId.equals(subXCV.getId())) {
				XmlRFC rfc = subXCV.getRFC();
				assertNotNull(rfc);
				assertEquals(Indication.PASSED, rfc.getConclusion().getIndication());

				boolean revocationFreshnessCheckFound = false;
				boolean revocationFreshnessNextUpdateCheckFound = false;
				for (XmlConstraint xmlConstraint : rfc.getConstraint()) {
					if (MessageTag.BBB_RFC_IRIF.getId().equals(xmlConstraint.getName().getKey())) {
						assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
						revocationFreshnessCheckFound = true;
					} else if (MessageTag.BBB_RFC_IRIF_TUNU.getId().equals(xmlConstraint.getName().getKey())) {
						revocationFreshnessNextUpdateCheckFound = true;
					}
				}
				assertTrue(revocationFreshnessCheckFound);
				assertFalse(revocationFreshnessNextUpdateCheckFound);

				signingCertificateFound = true;

			} else if (caCertificateId.equals(subXCV.getId())) {
				XmlRFC rfc = subXCV.getRFC();
				assertNotNull(rfc);
				assertEquals(Indication.PASSED, rfc.getConclusion().getIndication());

				boolean revocationFreshnessCheckFound = false;
				boolean revocationFreshnessNextUpdateCheckFound = false;
				for (XmlConstraint xmlConstraint : rfc.getConstraint()) {
					if (MessageTag.BBB_RFC_IRIF_TUNU.getId().equals(xmlConstraint.getName().getKey())) {
						assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
						revocationFreshnessNextUpdateCheckFound = true;
					} else if (MessageTag.BBB_RFC_IRIF.getId().equals(xmlConstraint.getName().getKey())) {
						revocationFreshnessCheckFound = true;
					}
				}
				assertFalse(revocationFreshnessCheckFound);
				assertTrue(revocationFreshnessNextUpdateCheckFound);

				caCertificateFound = true;

			} else {
				XmlRFC rfc = subXCV.getRFC();
				assertNull(rfc);

				rootCertificateFound = true;
			}
		}
		assertTrue(signingCertificateFound);
		assertTrue(caCertificateFound);
		assertTrue(rootCertificateFound);

		checkReports(reports);
	}

	@Test
	public void signatureWithMD2Test() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		xmlSignature.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.MD2);

		xmlSignature.getFoundTimestamps().clear();
		diagnosticData.getUsedTimestamps().clear();

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.MD2, MessageTag.ACCM_POS_SIG_SIG)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BSV_ICTGTNACCET_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);
		assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, signatureBBB.getConclusion().getSubIndication());

		XmlSAV signatureSAV = signatureBBB.getSAV();
		assertNotNull(signatureSAV);
		assertEquals(Indication.INDETERMINATE, signatureSAV.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, signatureSAV.getConclusion().getSubIndication());

		boolean cryptoCheckFound = false;
		for (XmlConstraint constraint : signatureSAV.getConstraint()) {
			if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.MD2, MessageTag.ACCM_POS_SIG_SIG),
						constraint.getError().getValue());
				cryptoCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(cryptoCheckFound);

		assertEquals(1, detailedReport.getSignatures().size());
		XmlValidationProcessBasicSignature validationProcessBasicSignature = detailedReport.getSignatures().get(0).getValidationProcessBasicSignature();
		assertNotNull(validationProcessBasicSignature);
		assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, validationProcessBasicSignature.getConclusion().getSubIndication());

		boolean contentTstBasicValidationFound = false;
		boolean checkAgainstContentTstFound = false;
		for (XmlConstraint constraint : validationProcessBasicSignature.getConstraint()) {
			if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
				contentTstBasicValidationFound = true;
			} else if (MessageTag.BSV_ICTGTNACCET.getId().equals(constraint.getName().getKey())) {
				checkAgainstContentTstFound = true;
			}
		}
		assertFalse(contentTstBasicValidationFound);
		assertFalse(checkAgainstContentTstFound);

		checkReports(reports);
	}

	@Test
	public void signatureWithMD2AndContentTstTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		xmlSignature.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.MD2);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.MD2, MessageTag.ACCM_POS_SIG_SIG)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BSV_ICTGTNACCET_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);
		assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, signatureBBB.getConclusion().getSubIndication());

		XmlSAV signatureSAV = signatureBBB.getSAV();
		assertNotNull(signatureSAV);
		assertEquals(Indication.INDETERMINATE, signatureSAV.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, signatureSAV.getConclusion().getSubIndication());

		boolean cryptoCheckFound = false;
		for (XmlConstraint constraint : signatureSAV.getConstraint()) {
			if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.MD2, MessageTag.ACCM_POS_SIG_SIG),
						constraint.getError().getValue());
				cryptoCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(cryptoCheckFound);

		assertEquals(1, detailedReport.getSignatures().size());
		XmlValidationProcessBasicSignature validationProcessBasicSignature = detailedReport.getSignatures().get(0).getValidationProcessBasicSignature();
		assertNotNull(validationProcessBasicSignature);
		assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE, validationProcessBasicSignature.getConclusion().getSubIndication());

		boolean contentTstBasicValidationFound = false;
		boolean checkAgainstContentTstFound = false;
		for (XmlConstraint constraint : validationProcessBasicSignature.getConstraint()) {
			if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				contentTstBasicValidationFound = true;
			} else if (MessageTag.BSV_ICTGTNACCET.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BSV_ICTGTNACCET_ANS.getId(), constraint.getError().getKey());
				checkAgainstContentTstFound = true;
			}
		}
		assertTrue(contentTstBasicValidationFound);
		assertTrue(checkAgainstContentTstFound);

		checkReports(reports);
	}

	@Test
	public void signatureWithMD2AndSHA3with224ContentTstTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		xmlSignature.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.MD2);

		XmlTimestamp xmlTimestamp = xmlSignature.getFoundTimestamps().get(0).getTimestamp();
		xmlTimestamp.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA3_224);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.MD2, MessageTag.ACCM_POS_SIG_SIG)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BSV_ICTGTNACCET_ANS)));

		eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp contentTst = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0);
		assertEquals(Indication.INDETERMINATE, contentTst.getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, contentTst.getSubIndication());
		assertTrue(checkMessageValuePresence(convertMessages(contentTst.getAdESValidationDetails().getError()),
				i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.SHA3_224.getName(), MessageTag.ACCM_POS_TST_SIG)));

		DetailedReport detailedReport = reports.getDetailedReport();

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);
		assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, signatureBBB.getConclusion().getSubIndication());

		XmlSAV signatureSAV = signatureBBB.getSAV();
		assertNotNull(signatureSAV);
		assertEquals(Indication.INDETERMINATE, signatureSAV.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, signatureSAV.getConclusion().getSubIndication());

		boolean cryptoCheckFound = false;
		for (XmlConstraint constraint : signatureSAV.getConstraint()) {
			if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.MD2, MessageTag.ACCM_POS_SIG_SIG),
						constraint.getError().getValue());
				cryptoCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(cryptoCheckFound);

		XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
		assertNotNull(timestampBBB);
		assertEquals(Indication.INDETERMINATE, timestampBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, timestampBBB.getConclusion().getSubIndication());

		XmlSAV timestampSAV = timestampBBB.getSAV();
		assertNotNull(timestampSAV);
		assertEquals(Indication.INDETERMINATE, timestampSAV.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, timestampSAV.getConclusion().getSubIndication());

		boolean cryptoCheckForTstFound = false;
		for (XmlConstraint constraint : timestampSAV.getConstraint()) {
			if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.SHA3_224.getName(), MessageTag.ACCM_POS_TST_SIG),
						constraint.getError().getValue());
				cryptoCheckForTstFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(cryptoCheckForTstFound);

		assertEquals(1, detailedReport.getSignatures().size());
		XmlValidationProcessBasicSignature validationProcessBasicSignature = detailedReport.getSignatures().get(0).getValidationProcessBasicSignature();
		assertNotNull(validationProcessBasicSignature);
		assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, validationProcessBasicSignature.getConclusion().getSubIndication());

		boolean contentTstBasicValidationFound = false;
		boolean checkAgainstContentTstFound = false;
		for (XmlConstraint constraint : validationProcessBasicSignature.getConstraint()) {
			if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
				contentTstBasicValidationFound = true;
			} else if (MessageTag.BSV_ICTGTNACCET.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BSV_ICTGTNACCET_ANS.getId(), constraint.getError().getKey());
				checkAgainstContentTstFound = true;
			}
		}
		assertTrue(contentTstBasicValidationFound);
		assertFalse(checkAgainstContentTstFound);

		checkReports(reports);
	}

	@Test
	public void jadesEcdsaTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_jades_valid.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		xmlSignature.getBasicSignature().setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.ECDSA);
		xmlSignature.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA256);
		xmlSignature.getBasicSignature().setKeyLengthUsedToSignThisToken("256");

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getSignedAttributes().setEllipticCurveKeySize(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

		XmlFC xmlFC = signatureBBB.getFC();
		assertNotNull(xmlFC);
		assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

		boolean ellipticCurveCheckFound = false;
		for (XmlConstraint constraint : xmlFC.getConstraint()) {
			if (MessageTag.BBB_FC_IECKSCDA.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				assertEquals(i18nProvider.getMessage(MessageTag.SIGNATURE_ALGORITHM_WITH_KEY_SIZE, SignatureAlgorithm.ECDSA_SHA256.getName(), "256"),
						constraint.getAdditionalInfo());
				ellipticCurveCheckFound = true;
				break;
			}
		}
		assertTrue(ellipticCurveCheckFound);

		checkReports(reports);
	}

	@Test
	public void jadesEcdsaInvalidKeySizeTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_jades_valid.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		xmlSignature.getBasicSignature().setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.ECDSA);
		xmlSignature.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA512);
		xmlSignature.getBasicSignature().setKeyLengthUsedToSignThisToken("256");

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getSignedAttributes().setEllipticCurveKeySize(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_IECKSCDA_ANS5)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, signatureBBB.getConclusion().getSubIndication());
		assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.BBB_FC_IECKSCDA_ANS5)));

		XmlFC xmlFC = signatureBBB.getFC();
		assertNotNull(xmlFC);
		assertEquals(Indication.FAILED, xmlFC.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, xmlFC.getConclusion().getSubIndication());
		assertTrue(checkMessageValuePresence(convert(xmlFC.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.BBB_FC_IECKSCDA_ANS5)));

		boolean ellipticCurveCheckFound = false;
		for (XmlConstraint constraint : xmlFC.getConstraint()) {
			if (MessageTag.BBB_FC_IECKSCDA.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_FC_IECKSCDA_ANS5.getId(), constraint.getError().getKey());
				assertEquals(i18nProvider.getMessage(MessageTag.SIGNATURE_ALGORITHM_WITH_KEY_SIZE, SignatureAlgorithm.ECDSA_SHA512.getName(), "256"),
						constraint.getAdditionalInfo());
				ellipticCurveCheckFound = true;
				break;
			}
		}
		assertTrue(ellipticCurveCheckFound);

		checkReports(reports);
	}

	@Test
	public void jadesEcdsaUnauthorizedDigestAlgoTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_jades_valid.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		xmlSignature.getBasicSignature().setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.ECDSA);
		xmlSignature.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA224);
		xmlSignature.getBasicSignature().setKeyLengthUsedToSignThisToken("256");

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getSignedAttributes().setEllipticCurveKeySize(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_IECKSCDA_ANS4)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, signatureBBB.getConclusion().getSubIndication());
		assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.BBB_FC_IECKSCDA_ANS4)));

		XmlFC xmlFC = signatureBBB.getFC();
		assertNotNull(xmlFC);
		assertEquals(Indication.FAILED, xmlFC.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, xmlFC.getConclusion().getSubIndication());
		assertTrue(checkMessageValuePresence(convert(xmlFC.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.BBB_FC_IECKSCDA_ANS4)));

		boolean ellipticCurveCheckFound = false;
		for (XmlConstraint constraint : xmlFC.getConstraint()) {
			if (MessageTag.BBB_FC_IECKSCDA.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_FC_IECKSCDA_ANS4.getId(), constraint.getError().getKey());
				assertEquals(i18nProvider.getMessage(MessageTag.SIGNATURE_ALGORITHM_WITH_KEY_SIZE, SignatureAlgorithm.ECDSA_SHA224.getName(), "256"),
						constraint.getAdditionalInfo());
				ellipticCurveCheckFound = true;
				break;
			}
		}
		assertTrue(ellipticCurveCheckFound);

		checkReports(reports);
	}

	@Test
	public void jadesRsaTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_jades_valid.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		xmlSignature.getBasicSignature().setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.RSA);
		xmlSignature.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA512);
		xmlSignature.getBasicSignature().setKeyLengthUsedToSignThisToken("2048");

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getSignedAttributes().setEllipticCurveKeySize(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

		XmlFC xmlFC = signatureBBB.getFC();
		assertNotNull(xmlFC);
		assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

		boolean ellipticCurveCheckFound = false;
		for (XmlConstraint constraint : xmlFC.getConstraint()) {
			if (MessageTag.BBB_FC_IECKSCDA.getId().equals(constraint.getName().getKey())) {
				ellipticCurveCheckFound = true;
				break;
			}
		}
		assertFalse(ellipticCurveCheckFound);

		checkReports(reports);
	}

	@Test
	public void xadesEcdsaTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		xmlSignature.getBasicSignature().setEncryptionAlgoUsedToSignThisToken(EncryptionAlgorithm.ECDSA);
		xmlSignature.getBasicSignature().setDigestAlgoUsedToSignThisToken(DigestAlgorithm.SHA512);
		xmlSignature.getBasicSignature().setKeyLengthUsedToSignThisToken("256");

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getSignedAttributes().setEllipticCurveKeySize(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

		XmlFC xmlFC = signatureBBB.getFC();
		assertNotNull(xmlFC);
		assertEquals(Indication.PASSED, xmlFC.getConclusion().getIndication());

		boolean ellipticCurveCheckFound = false;
		for (XmlConstraint constraint : xmlFC.getConstraint()) {
			if (MessageTag.BBB_FC_IECKSCDA.getId().equals(constraint.getName().getKey())) {
				ellipticCurveCheckFound = true;
				break;
			}
		}
		assertFalse(ellipticCurveCheckFound);

		checkReports(reports);
	}

	@Test
	public void asicNoMimetypeSkipCheckTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/asic-s-xades-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
		containerInfo.setMimeTypeFilePresent(false);
		containerInfo.setMimeTypeContent(null);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		ContainerConstraints containerConstraints = validationPolicy.getContainerConstraints();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(null);
		containerConstraints.setMimeTypeFilePresent(levelConstraint);

		MultiValuesConstraint acceptableMimetype = new MultiValuesConstraint();
		acceptableMimetype.getId().add("application/vnd.etsi.asic-s+zip");
		acceptableMimetype.getId().add("application/vnd.etsi.asic-e+zip");
		acceptableMimetype.setLevel(Level.FAIL);
		containerConstraints.setAcceptableMimeTypeFileContent(acceptableMimetype);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		checkReports(reports);
	}

	@Test
	public void asicNoMimetypeFailLevelTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/asic-s-xades-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
		containerInfo.setMimeTypeFilePresent(false);
		containerInfo.setMimeTypeContent(null);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		ContainerConstraints containerConstraints = validationPolicy.getContainerConstraints();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		containerConstraints.setMimeTypeFilePresent(levelConstraint);

		MultiValuesConstraint acceptableMimetype = new MultiValuesConstraint();
		acceptableMimetype.getId().add("application/vnd.etsi.asic-s+zip");
		acceptableMimetype.getId().add("application/vnd.etsi.asic-e+zip");
		acceptableMimetype.setLevel(Level.FAIL);
		containerConstraints.setAcceptableMimeTypeFileContent(acceptableMimetype);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_ITMFP_ANS)));

		checkReports(reports);
	}

	@Test
	public void asicNotAcceptableMimeTypeTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/asic-s-xades-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
		containerInfo.setMimeTypeFilePresent(true);
		containerInfo.setMimeTypeContent("test-content");

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		ContainerConstraints containerConstraints = validationPolicy.getContainerConstraints();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		containerConstraints.setMimeTypeFilePresent(levelConstraint);

		MultiValuesConstraint acceptableMimetype = new MultiValuesConstraint();
		acceptableMimetype.getId().add("application/vnd.etsi.asic-s+zip");
		acceptableMimetype.getId().add("application/vnd.etsi.asic-e+zip");
		acceptableMimetype.setLevel(Level.FAIL);
		containerConstraints.setAcceptableMimeTypeFileContent(acceptableMimetype);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_IEMCF_ANS)));

		checkReports(reports);
	}

	@Test
	public void asicZipCommentSkipCheckTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/asic-s-xades-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
		containerInfo.setZipComment(null);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		ContainerConstraints containerConstraints = validationPolicy.getContainerConstraints();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(null);
		containerConstraints.setZipCommentPresent(levelConstraint);

		MultiValuesConstraint acceptableZipComment = new MultiValuesConstraint();
		acceptableZipComment.getId().add("application/vnd.etsi.asic-s+zip");
		acceptableZipComment.getId().add("application/vnd.etsi.asic-e+zip");
		acceptableZipComment.setLevel(Level.FAIL);
		containerConstraints.setAcceptableZipComment(acceptableZipComment);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		checkReports(reports);
	}

	@Test
	public void asicZipCommentFailLevelTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/asic-s-xades-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
		containerInfo.setZipComment(null);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		ContainerConstraints containerConstraints = validationPolicy.getContainerConstraints();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		containerConstraints.setZipCommentPresent(levelConstraint);

		MultiValuesConstraint acceptableZipComment = new MultiValuesConstraint();
		acceptableZipComment.getId().add("application/vnd.etsi.asic-s+zip");
		acceptableZipComment.getId().add("application/vnd.etsi.asic-e+zip");
		acceptableZipComment.setLevel(Level.FAIL);
		containerConstraints.setAcceptableZipComment(acceptableZipComment);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_ITZCP_ANS)));

		checkReports(reports);
	}

	@Test
	public void asicNotAcceptableZipCommentTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/asic-s-xades-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
		containerInfo.setZipComment("test-comment");

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		ContainerConstraints containerConstraints = validationPolicy.getContainerConstraints();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		containerConstraints.setZipCommentPresent(levelConstraint);

		MultiValuesConstraint acceptableZipComment = new MultiValuesConstraint();
		acceptableZipComment.getId().add("application/vnd.etsi.asic-s+zip");
		acceptableZipComment.getId().add("application/vnd.etsi.asic-e+zip");
		acceptableZipComment.setLevel(Level.FAIL);
		containerConstraints.setAcceptableZipComment(acceptableZipComment);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_ITEZCF_ANS)));

		checkReports(reports);
	}

	@Test
	public void dss2214NoRevocationDataTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_no_revocation_data.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setRevocationDataAvailable(levelConstraint);
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setAcceptableRevocationDataFound(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(3, xcv.getSubXCV().size());

		boolean revocationDataPresentCheck = false;
		boolean acceptableRevocationDataCheck = false;
		XmlSubXCV subXCV = xcv.getSubXCV().iterator().next();
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_IRDPFC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_IRDPFC_ANS.getId(), constraint.getWarning().getKey());
				revocationDataPresentCheck = true;
			} else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getWarning().getKey());
				acceptableRevocationDataCheck = true;
			}
		}
		assertTrue(revocationDataPresentCheck);
		assertFalse(acceptableRevocationDataCheck);

		assertEquals(1, detailedReport.getSignatures().size());
		XmlValidationProcessLongTermData ltvProcess = detailedReport.getSignatures().iterator().next().getValidationProcessLongTermData();
		assertNotNull(ltvProcess);

		revocationDataPresentCheck = false;
		acceptableRevocationDataCheck = false;
		for (XmlConstraint constraint : ltvProcess.getConstraint()) {
			if (subXCV.getId().equals(constraint.getId())) {
				if (MessageTag.BBB_XCV_IRDPFC.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.WARNING, constraint.getStatus());
					assertEquals(MessageTag.BBB_XCV_IRDPFC_ANS.getId(), constraint.getWarning().getKey());
					revocationDataPresentCheck = true;
				} else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.WARNING, constraint.getStatus());
					assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getWarning().getKey());
					acceptableRevocationDataCheck = true;
				}
			}
		}
		assertTrue(revocationDataPresentCheck);
		assertFalse(acceptableRevocationDataCheck);

		checkReports(reports);
	}

	@Test
	public void dss2214NoRevocationDataAvailableCheckSkippedTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_no_revocation_data.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setRevocationDataAvailable(null);
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setAcceptableRevocationDataFound(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(3, xcv.getSubXCV().size());

		boolean revocationDataPresentCheck = false;
		boolean acceptableRevocationDataCheck = false;
		XmlSubXCV subXCV = xcv.getSubXCV().iterator().next();
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_IRDPFC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_IRDPFC_ANS.getId(), constraint.getWarning().getKey());
				revocationDataPresentCheck = true;
			} else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getWarning().getKey());
				acceptableRevocationDataCheck = true;
			}
		}
		assertFalse(revocationDataPresentCheck);
		assertFalse(acceptableRevocationDataCheck);

		assertEquals(1, detailedReport.getSignatures().size());
		XmlValidationProcessLongTermData ltvProcess = detailedReport.getSignatures().iterator().next().getValidationProcessLongTermData();
		assertNotNull(ltvProcess);

		revocationDataPresentCheck = false;
		acceptableRevocationDataCheck = false;
		for (XmlConstraint constraint : ltvProcess.getConstraint()) {
			if (subXCV.getId().equals(constraint.getId())) {
				if (MessageTag.BBB_XCV_IRDPFC.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.WARNING, constraint.getStatus());
					assertEquals(MessageTag.BBB_XCV_IRDPFC_ANS.getId(), constraint.getWarning().getKey());
					revocationDataPresentCheck = true;
				} else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.WARNING, constraint.getStatus());
					assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getWarning().getKey());
					acceptableRevocationDataCheck = true;
				}
			}
		}
		assertFalse(revocationDataPresentCheck);
		assertFalse(acceptableRevocationDataCheck);

		checkReports(reports);
	}

	@Test
	public void dss2214BadRevocationDataTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_bad_revocation_data.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setRevocationDataAvailable(levelConstraint);
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setAcceptableRevocationDataFound(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(3, xcv.getSubXCV().size());

		boolean revocationDataPresentCheck = false;
		boolean acceptableRevocationDataCheck = false;
		XmlSubXCV subXCV = xcv.getSubXCV().iterator().next();
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_IRDPFC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				revocationDataPresentCheck = true;
			} else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getWarning().getKey());
				acceptableRevocationDataCheck = true;
			}
		}
		assertTrue(revocationDataPresentCheck);
		assertTrue(acceptableRevocationDataCheck);

		assertEquals(1, detailedReport.getSignatures().size());
		XmlValidationProcessLongTermData ltvProcess = detailedReport.getSignatures().iterator().next().getValidationProcessLongTermData();
		assertNotNull(ltvProcess);

		revocationDataPresentCheck = false;
		acceptableRevocationDataCheck = false;
		for (XmlConstraint constraint : ltvProcess.getConstraint()) {
			if (subXCV.getId().equals(constraint.getId())) {
				if (MessageTag.BBB_XCV_IRDPFC.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					revocationDataPresentCheck = true;
				} else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.WARNING, constraint.getStatus());
					assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getWarning().getKey());
					acceptableRevocationDataCheck = true;
				}
			}
		}
		assertTrue(revocationDataPresentCheck);
		assertTrue(acceptableRevocationDataCheck);

		checkReports(reports);
	}

	@Test
	public void dss2824PassedValidationWithArchiveCutoffTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_ocsp_with_archivecutoff.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		assertNotNull(signingCertificate);
		List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
		assertEquals(1, certificateRevocationData.size());
		CertificateRevocationWrapper certificateRevocation = certificateRevocationData.get(0);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		List<XmlSubXCV> subXCV = xcv.getSubXCV();
		assertEquals(2, subXCV.size());

		XmlSubXCV xmlSubXCV = subXCV.get(0);
		XmlCRS crs = xmlSubXCV.getCRS();
		assertNotNull(crs);

		List<XmlRAC> racs = crs.getRAC();
		assertEquals(1, racs.size());

		XmlRAC xmlRAC = racs.get(0);
		boolean consistencyCheckFound = false;
		for (XmlConstraint constraint : xmlRAC.getConstraint()) {
			if (MessageTag.BBB_XCV_IRDC.getId().equals(constraint.getName().getKey())) {
				assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_OCSP,
						ValidationProcessUtils.getFormattedDate(certificateRevocation.getThisUpdate()),
						ValidationProcessUtils.getFormattedDate(certificateRevocation.getArchiveCutOff()),
						ValidationProcessUtils.getFormattedDate(signingCertificate.getNotBefore()),
						ValidationProcessUtils.getFormattedDate(signingCertificate.getNotAfter())), constraint.getAdditionalInfo());
				consistencyCheckFound = true;
			}
		}
		assertTrue(consistencyCheckFound);

		checkReports(reports);
	}

	@Test
	public void dss2824RevocationValidAtValidationTimeTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		assertNotNull(signingCertificate);
		List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
		assertEquals(1, certificateRevocationData.size());
		CertificateRevocationWrapper certificateRevocation = certificateRevocationData.get(0);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);

		List<XmlSubXCV> subXCV = xcv.getSubXCV();
		assertEquals(3, subXCV.size());

		XmlSubXCV xmlSubXCV = subXCV.get(0);
		XmlCRS crs = xmlSubXCV.getCRS();
		assertNotNull(crs);

		List<XmlRAC> racs = crs.getRAC();
		assertEquals(1, racs.size());

		XmlRAC xmlRAC = racs.get(0);
		boolean consistencyCheckFound = false;
		for (XmlConstraint constraint : xmlRAC.getConstraint()) {
			if (MessageTag.BBB_XCV_IRDC.getId().equals(constraint.getName().getKey())) {
				assertEquals(i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT,
						ValidationProcessUtils.getFormattedDate(certificateRevocation.getThisUpdate()),
						ValidationProcessUtils.getFormattedDate(signingCertificate.getNotBefore()),
						ValidationProcessUtils.getFormattedDate(signingCertificate.getNotAfter())), constraint.getAdditionalInfo());
				consistencyCheckFound = true;
			}
		}
		assertTrue(consistencyCheckFound);

		checkReports(reports);
	}

	@Test
	public void dss2214BadRevocationDataNoPresenceCheckTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_bad_revocation_data.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setRevocationDataAvailable(null);
		signatureConstraints.getBasicSignatureConstraints().getSigningCertificate().setAcceptableRevocationDataFound(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(3, xcv.getSubXCV().size());

		boolean revocationDataPresentCheck = false;
		boolean acceptableRevocationDataCheck = false;
		XmlSubXCV subXCV = xcv.getSubXCV().iterator().next();
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_IRDPFC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				revocationDataPresentCheck = true;
			} else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getWarning().getKey());
				acceptableRevocationDataCheck = true;
			}
		}
		assertFalse(revocationDataPresentCheck);
		assertTrue(acceptableRevocationDataCheck);

		assertEquals(1, detailedReport.getSignatures().size());
		XmlValidationProcessLongTermData ltvProcess = detailedReport.getSignatures().iterator().next().getValidationProcessLongTermData();
		assertNotNull(ltvProcess);

		revocationDataPresentCheck = false;
		acceptableRevocationDataCheck = false;
		for (XmlConstraint constraint : ltvProcess.getConstraint()) {
			if (subXCV.getId().equals(constraint.getId())) {
				if (MessageTag.BBB_XCV_IRDPFC.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					revocationDataPresentCheck = true;
				} else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.WARNING, constraint.getStatus());
					assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getWarning().getKey());
					acceptableRevocationDataCheck = true;
				}
			}
		}
		assertFalse(revocationDataPresentCheck);
		assertTrue(acceptableRevocationDataCheck);

		checkReports(reports);
	}

	@Test
	public void mraQeSigTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/mra/diag-data-mra-qesig.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		assertEquals(0, Utils.collectionSize(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertEquals(0, Utils.collectionSize(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
		assertEquals(1, Utils.collectionSize(simpleReport.getQualificationInfo(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationInfo(
				simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);

		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		List<TrustServiceWrapper> trustServices = signingCertificate.getTrustServices();
		String tlId = trustServices.get(0).getTrustedList().getId();

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlTLAnalysis tlAnalysis = detailedReport.getTLAnalysisById(tlId);
		assertNotNull(tlAnalysis);

		boolean mraFound = false;
		for (XmlConstraint constraint : tlAnalysis.getConstraint()) {
			if (MessageTag.QUAL_TL_IMRA.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
				assertEquals(MessageTag.QUAL_TL_IMRA_ANS.getId(), constraint.getInfo().getKey());
				mraFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(mraFound);

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
		assertEquals(SignatureQualification.QESIG, validationSignatureQualification.getSignatureQualification());

		assertEquals(Indication.PASSED, validationSignatureQualification.getConclusion().getIndication());
		assertTrue(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getInfos()),
				i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));

		checkReports(reports);
	}

	@Test
	public void noMraAdeSigTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/mra/diag-data-no-mra-adesig.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		assertEquals(1, Utils.collectionSize(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertEquals(0, Utils.collectionSize(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
		assertEquals(1, Utils.collectionSize(simpleReport.getQualificationInfo(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationInfo(
				simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);

		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		List<TrustServiceWrapper> trustServices = signingCertificate.getTrustServices();
		String tlId = trustServices.get(0).getTrustedList().getId();

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlTLAnalysis tlAnalysis = detailedReport.getTLAnalysisById(tlId);
		assertNotNull(tlAnalysis);

		boolean mraFound = false;
		for (XmlConstraint constraint : tlAnalysis.getConstraint()) {
			if (MessageTag.QUAL_TL_IMRA.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
				assertEquals(MessageTag.QUAL_TL_IMRA_ANS.getId(), constraint.getInfo().getKey());
				mraFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(mraFound);

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
		assertEquals(SignatureQualification.ADESIG, validationSignatureQualification.getSignatureQualification());

		assertEquals(Indication.FAILED, validationSignatureQualification.getConclusion().getIndication());
		assertTrue(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getInfos()),
				i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));
		assertTrue(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.QUAL_HAS_METS_ANS)));

		List<XmlValidationCertificateQualification> validationCertificateQualification = validationSignatureQualification.getValidationCertificateQualification();
		assertEquals(2, validationCertificateQualification.size());

		for (XmlValidationCertificateQualification certificateQualification : validationCertificateQualification) {
			boolean mraTrustServiceCheckFound = false;
			for (XmlConstraint constraint : certificateQualification.getConstraint()) {
				if (MessageTag.QUAL_HAS_METS.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
					assertEquals(MessageTag.QUAL_HAS_METS_ANS.getId(), constraint.getError().getKey());
					mraTrustServiceCheckFound = true;
				} else {
					assertEquals(XmlStatus.OK, constraint.getStatus());
				}
			}
			assertTrue(mraTrustServiceCheckFound);
		}

		checkReports(reports);
	}

	@Test
	public void mraAfterCertIssuanceTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/mra/diag-data-mra-qesig.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate xmlSigningCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
		XmlTrustService trustService = xmlSigningCertificate.getTrustServiceProviders().get(0).getTrustServices().get(0);
		trustService.getMRATrustServiceMapping().setEquivalenceStatusStartingTime(new Date());

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		assertEquals(1, Utils.collectionSize(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertEquals(0, Utils.collectionSize(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
		assertEquals(1, Utils.collectionSize(simpleReport.getQualificationInfo(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationInfo(
				simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);

		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		List<TrustServiceWrapper> trustServices = signingCertificate.getTrustServices();
		String tlId = trustServices.get(0).getTrustedList().getId();

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlTLAnalysis tlAnalysis = detailedReport.getTLAnalysisById(tlId);
		assertNotNull(tlAnalysis);

		boolean mraFound = false;
		for (XmlConstraint constraint : tlAnalysis.getConstraint()) {
			if (MessageTag.QUAL_TL_IMRA.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
				assertEquals(MessageTag.QUAL_TL_IMRA_ANS.getId(), constraint.getInfo().getKey());
				mraFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(mraFound);

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
		assertEquals(SignatureQualification.ADESIG, validationSignatureQualification.getSignatureQualification());

		assertEquals(Indication.FAILED, validationSignatureQualification.getConclusion().getIndication());
		assertTrue(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getInfos()),
				i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));
		assertTrue(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.QUAL_HAS_METS_ANS)));

		List<XmlValidationCertificateQualification> validationCertificateQualification = validationSignatureQualification.getValidationCertificateQualification();
		assertEquals(2, validationCertificateQualification.size());

		for (XmlValidationCertificateQualification certificateQualification : validationCertificateQualification) {
			boolean mraTrustServiceCheckFound = false;
			for (XmlConstraint constraint : certificateQualification.getConstraint()) {
				if (MessageTag.QUAL_HAS_METS.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
					assertEquals(MessageTag.QUAL_HAS_METS_ANS.getId(), constraint.getError().getKey());
					mraTrustServiceCheckFound = true;
				} else {
					assertEquals(XmlStatus.OK, constraint.getStatus());
				}
			}
			assertTrue(mraTrustServiceCheckFound);
		}

		checkReports(reports);
	}

	@Test
	public void mraWithQTstsTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/mra/diag-data-mra-with-qtsts.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.ADESEAL, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		assertEquals(1, Utils.collectionSize(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertEquals(2, Utils.collectionSize(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
		assertEquals(1, Utils.collectionSize(simpleReport.getQualificationInfo(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationInfo(
				simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));

		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		assertEquals(2, signatureTimestamps.size());
		for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp : signatureTimestamps) {
			assertEquals(Indication.PASSED, timestamp.getIndication());
			assertEquals(TimestampQualification.QTSA, timestamp.getTimestampLevel().getValue());

			assertEquals(0, Utils.collectionSize(timestamp.getQualificationDetails().getError()));
			assertEquals(0, Utils.collectionSize(timestamp.getQualificationDetails().getWarning()));
			assertEquals(1, Utils.collectionSize(timestamp.getQualificationDetails().getInfo()));
			assertTrue(checkMessageValuePresence(convertMessages(timestamp.getQualificationDetails().getInfo()),
					i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));
		}

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);

		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		List<TrustServiceWrapper> trustServices = signingCertificate.getTrustServices();
		String tlId = trustServices.get(0).getTrustedList().getId();

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlTLAnalysis tlAnalysis = detailedReport.getTLAnalysisById(tlId);
		assertNotNull(tlAnalysis);

		boolean mraFound = false;
		for (XmlConstraint constraint : tlAnalysis.getConstraint()) {
			if (MessageTag.QUAL_TL_IMRA.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
				assertEquals(MessageTag.QUAL_TL_IMRA_ANS.getId(), constraint.getInfo().getKey());
				mraFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(mraFound);

		assertEquals(2, detailedReport.getTimestampIds().size());
		for (String tstId : detailedReport.getTimestampIds()) {
			assertEquals(TimestampQualification.QTSA, detailedReport.getTimestampQualification(tstId));
			eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = detailedReport.getXmlTimestampById(tstId);
			XmlValidationTimestampQualification validationTimestampQualification = xmlTimestamp.getValidationTimestampQualification();
			assertNotNull(validationTimestampQualification);

			List<XmlValidationTimestampQualificationAtTime> timestampQualificationsAtTime = validationTimestampQualification.getValidationTimestampQualificationAtTime();
			assertEquals(2, timestampQualificationsAtTime.size());

			for (XmlValidationTimestampQualificationAtTime timestampQualificationAtTime : timestampQualificationsAtTime) {
				boolean mraTrustServiceCheckFound = false;
				for (XmlConstraint constraint : timestampQualificationAtTime.getConstraint()) {
					if (MessageTag.QUAL_HAS_METS.getId().equals(constraint.getName().getKey())) {
						mraTrustServiceCheckFound = true;
					}
					assertEquals(XmlStatus.OK, constraint.getStatus());
				}
				assertTrue(mraTrustServiceCheckFound);
			}
		}

		checkReports(reports);
	}

	@Test
	public void mraWithTstsTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/mra/diag-data-mra-with-tsts.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.ADESEAL, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		assertEquals(1, Utils.collectionSize(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertEquals(2, Utils.collectionSize(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
		assertEquals(1, Utils.collectionSize(simpleReport.getQualificationInfo(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationInfo(
				simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));

		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		assertEquals(2, signatureTimestamps.size());
		for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp : signatureTimestamps) {
			assertEquals(Indication.PASSED, timestamp.getIndication());
			assertEquals(TimestampQualification.TSA, timestamp.getTimestampLevel().getValue());

			assertEquals(1, Utils.collectionSize(timestamp.getQualificationDetails().getError()));
			assertEquals(0, Utils.collectionSize(timestamp.getQualificationDetails().getWarning()));
			assertEquals(1, Utils.collectionSize(timestamp.getQualificationDetails().getInfo()));
			assertTrue(checkMessageValuePresence(convertMessages(timestamp.getQualificationDetails().getError()),
					i18nProvider.getMessage(MessageTag.QUAL_HAS_METS_ANS)));
			assertTrue(checkMessageValuePresence(convertMessages(timestamp.getQualificationDetails().getInfo()),
					i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));
		}

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);

		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		List<TrustServiceWrapper> trustServices = signingCertificate.getTrustServices();
		String tlId = trustServices.get(0).getTrustedList().getId();

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlTLAnalysis tlAnalysis = detailedReport.getTLAnalysisById(tlId);
		assertNotNull(tlAnalysis);

		boolean mraFound = false;
		for (XmlConstraint constraint : tlAnalysis.getConstraint()) {
			if (MessageTag.QUAL_TL_IMRA.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
				assertEquals(MessageTag.QUAL_TL_IMRA_ANS.getId(), constraint.getInfo().getKey());
				mraFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(mraFound);

		assertEquals(2, detailedReport.getTimestampIds().size());
		for (String tstId : detailedReport.getTimestampIds()) {
			assertEquals(TimestampQualification.TSA, detailedReport.getTimestampQualification(tstId));
			eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = detailedReport.getXmlTimestampById(tstId);
			XmlValidationTimestampQualification validationTimestampQualification = xmlTimestamp.getValidationTimestampQualification();
			assertNotNull(validationTimestampQualification);

			List<XmlValidationTimestampQualificationAtTime> timestampQualificationsAtTime = validationTimestampQualification.getValidationTimestampQualificationAtTime();
			assertEquals(2, timestampQualificationsAtTime.size());

			for (XmlValidationTimestampQualificationAtTime timestampQualificationAtTime : timestampQualificationsAtTime) {
				boolean mraTrustServiceCheckFound = false;
				for (XmlConstraint constraint : timestampQualificationAtTime.getConstraint()) {
					if (MessageTag.QUAL_HAS_METS.getId().equals(constraint.getName().getKey())) {
						assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
						assertEquals(MessageTag.QUAL_HAS_METS_ANS.getId(), constraint.getError().getKey());
						mraTrustServiceCheckFound = true;
					} else {
						assertEquals(XmlStatus.OK, constraint.getStatus());
					}
				}
				assertTrue(mraTrustServiceCheckFound);
			}
		}

		checkReports(reports);
	}

	@Test
	public void mraQeSigArt14Test() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/mra/diag-data-mra-qesig.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlTrustedList xmlTrustedList = xmlDiagnosticData.getTrustedLists().get(1);
		xmlTrustedList.setTSLType("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		assertEquals(0, Utils.collectionSize(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertEquals(0, Utils.collectionSize(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
		assertEquals(1, Utils.collectionSize(simpleReport.getQualificationInfo(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationInfo(
				simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS_V1)));

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);

		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		List<TrustServiceWrapper> trustServices = signingCertificate.getTrustServices();
		String tlId = trustServices.get(0).getTrustedList().getId();

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlTLAnalysis tlAnalysis = detailedReport.getTLAnalysisById(tlId);
		assertNotNull(tlAnalysis);

		boolean mraFound = false;
		for (XmlConstraint constraint : tlAnalysis.getConstraint()) {
			if (MessageTag.QUAL_TL_IMRA.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
				assertEquals(MessageTag.QUAL_TL_IMRA_ANS_V1.getId(), constraint.getInfo().getKey());
				mraFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(mraFound);

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
		assertEquals(SignatureQualification.QESIG, validationSignatureQualification.getSignatureQualification());

		assertEquals(Indication.PASSED, validationSignatureQualification.getConclusion().getIndication());
		assertTrue(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getInfos()),
				i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS_V1)));

		checkReports(reports);
	}

	@Test
	public void mraQeSigArt27Test() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/mra/diag-data-mra-qesig.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlTrustedList xmlTrustedList = xmlDiagnosticData.getTrustedLists().get(1);
		xmlTrustedList.setTSLType("http://ec.europa.eu/tools/lotl/mra/ades-lotl-tsl-type");

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		assertEquals(0, Utils.collectionSize(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertEquals(0, Utils.collectionSize(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
		assertEquals(1, Utils.collectionSize(simpleReport.getQualificationInfo(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationInfo(
				simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS_V2)));

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);

		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		List<TrustServiceWrapper> trustServices = signingCertificate.getTrustServices();
		String tlId = trustServices.get(0).getTrustedList().getId();

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlTLAnalysis tlAnalysis = detailedReport.getTLAnalysisById(tlId);
		assertNotNull(tlAnalysis);

		boolean mraFound = false;
		for (XmlConstraint constraint : tlAnalysis.getConstraint()) {
			if (MessageTag.QUAL_TL_IMRA.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
				assertEquals(MessageTag.QUAL_TL_IMRA_ANS_V2.getId(), constraint.getInfo().getKey());
				mraFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(mraFound);

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
		assertEquals(SignatureQualification.QESIG, validationSignatureQualification.getSignatureQualification());

		assertEquals(Indication.PASSED, validationSignatureQualification.getConclusion().getIndication());
		assertTrue(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getInfos()),
				i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS_V2)));

		checkReports(reports);
	}

	@Test
	public void mraCertEquivalenceRuleNotAppliedTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/mra/diag-data-mra-qesig-cert-rule-not-applied.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		assertEquals(0, Utils.collectionSize(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
		assertEquals(1, Utils.collectionSize(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationWarnings(
				simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_HAS_METS_HCCECBA_ANS_2, MRAEquivalenceContext.QC_COMPLIANCE.getUri())));
		assertEquals(1, Utils.collectionSize(simpleReport.getQualificationInfo(simpleReport.getFirstSignatureId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationInfo(
				simpleReport.getFirstSignatureId()), i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);

		DetailedReport detailedReport = reports.getDetailedReport();
		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();

		for (XmlValidationCertificateQualification certificateQualification : validationSignatureQualification.getValidationCertificateQualification()) {
			assertEquals(CertificateQualification.QCERT_FOR_ESIG_QSCD, certificateQualification.getCertificateQualification());

			boolean mraCertContentEquivalenceCheckFound = false;
			for (XmlConstraint constraint : certificateQualification.getConstraint()) {
				if (MessageTag.QUAL_HAS_METS_HCCECBA.getId().equals(constraint.getName().getKey())) {
					assertEquals(XmlStatus.WARNING, constraint.getStatus());
					assertEquals(MessageTag.QUAL_HAS_METS_HCCECBA_ANS_2.getId(), constraint.getWarning().getKey());
					mraCertContentEquivalenceCheckFound = true;
				} else {
					assertEquals(XmlStatus.OK, constraint.getStatus());
				}
			}
			assertTrue(mraCertContentEquivalenceCheckFound);
		}

		checkReports(reports);
	}

	@Test
	public void invalidByteRangeTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_pkcs7.xml"));
		assertNotNull(xmlDiagnosticData);

		List<eu.europa.esig.dss.diagnostic.jaxb.XmlSignature> xmlSignatures = xmlDiagnosticData.getSignatures();
		assertEquals(1, xmlSignatures.size());

		eu.europa.esig.dss.diagnostic.jaxb.XmlSignature xmlSignature = xmlSignatures.get(0);
		xmlSignature.getBasicSignature().setSignatureIntact(false);
		xmlSignature.getBasicSignature().setSignatureValid(false);

		XmlPDFSignatureDictionary pdfSignatureDictionary = xmlSignature.getPDFRevision().getPDFSignatureDictionary();
		pdfSignatureDictionary.setConsistent(false);

		XmlByteRange signatureByteRange = pdfSignatureDictionary.getSignatureByteRange();
		signatureByteRange.setValid(false);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setByteRange(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_IBRV_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlFC xmlFC = signatureBBB.getFC();
		assertNotNull(xmlFC);

		boolean byteRangeCheckFound = false;
		for (XmlConstraint constraint : xmlFC.getConstraint()) {
			if (MessageTag.BBB_FC_IBRV.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_FC_IBRV_ANS.getId(), constraint.getError().getKey());
				byteRangeCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(byteRangeCheckFound);

		checkReports(reports);
	}

	@Test
	public void invalidByteRangeWarnTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_pkcs7.xml"));
		assertNotNull(xmlDiagnosticData);

		List<eu.europa.esig.dss.diagnostic.jaxb.XmlSignature> xmlSignatures = xmlDiagnosticData.getSignatures();
		assertEquals(1, xmlSignatures.size());

		eu.europa.esig.dss.diagnostic.jaxb.XmlSignature xmlSignature = xmlSignatures.get(0);
		xmlSignature.getBasicSignature().setSignatureIntact(false);
		xmlSignature.getBasicSignature().setSignatureValid(false);

		XmlByteRange signatureByteRange = xmlSignature.getPDFRevision().getPDFSignatureDictionary().getSignatureByteRange();
		signatureByteRange.setValid(false);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setByteRange(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CRYPTO_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_IBRV_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_IBRV_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlFC xmlFC = signatureBBB.getFC();
		assertNotNull(xmlFC);

		boolean byteRangeCheckFound = false;
		for (XmlConstraint constraint : xmlFC.getConstraint()) {
			if (MessageTag.BBB_FC_IBRV.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.BBB_FC_IBRV_ANS.getId(), constraint.getWarning().getKey());
				byteRangeCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(byteRangeCheckFound);

		checkReports(reports);
	}

	@Test
	public void byteRangeCollisionTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_pades_lta_mod_tst.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlTimestamp xmlTimestamp = xmlDiagnosticData.getUsedTimestamps().get(1);
		XmlByteRange byteRange = xmlTimestamp.getPDFRevision().getPDFSignatureDictionary().getSignatureByteRange();
		byteRange.getValue().clear();
		byteRange.getValue().addAll(Arrays.asList(BigInteger.valueOf(0), BigInteger.valueOf(156500), BigInteger.valueOf(176500), BigInteger.valueOf(500)));

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setByteRangeCollision(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_DBTOOST_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, signatureBBB.getConclusion().getSubIndication());

		XmlFC fc = signatureBBB.getFC();
		assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());

		boolean byteRangeCollisionCheckFound = false;
		for (XmlConstraint constraint : fc.getConstraint()) {
			if (MessageTag.BBB_FC_DBTOOST.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_FC_DBTOOST_ANS.getId(), constraint.getError().getKey());
				byteRangeCollisionCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(byteRangeCollisionCheckFound);
	}

	@Test
	public void byteRangeAllDocumentTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_pades_lta_mod_tst.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlTimestamp xmlTimestamp = xmlDiagnosticData.getUsedTimestamps().get(1);
		XmlByteRange byteRange = xmlTimestamp.getPDFRevision().getPDFSignatureDictionary().getSignatureByteRange();
		byteRange.setValid(false);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setByteRangeAllDocument(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_DASTHVBR_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, signatureBBB.getConclusion().getSubIndication());

		XmlFC fc = signatureBBB.getFC();
		assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());

		boolean byteRangeAllDocumentCheckFound = false;
		for (XmlConstraint constraint : fc.getConstraint()) {
			if (MessageTag.BBB_FC_DASTHVBR.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_FC_DASTHVBR_ANS.getId(), constraint.getError().getKey());
				byteRangeAllDocumentCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(byteRangeAllDocumentCheckFound);
	}

	@Test
	public void pdfaValidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_pdfa.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		MultiValuesConstraint valuesConstraint = new MultiValuesConstraint();
		valuesConstraint.setLevel(Level.FAIL);
		valuesConstraint.getId().add("PDF/A-2A");
		valuesConstraint.getId().add("PDF/A-2B");
		valuesConstraint.getId().add("PDF/A-2U");
		validationPolicy.getPDFAConstraints().setAcceptablePDFAProfiles(valuesConstraint);

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getPDFAConstraints().setPDFACompliant(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);
		assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

		XmlFC fc = signatureBBB.getFC();
		assertEquals(Indication.PASSED, fc.getConclusion().getIndication());

		boolean pdfAFormatCheckFound = false;
		boolean pdfAComplianceCheckFound = false;
		for (XmlConstraint constraint : fc.getConstraint()) {
			if (MessageTag.BBB_FC_DDAPDFAF.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				pdfAFormatCheckFound = true;
			} else if (MessageTag.BBB_FC_IDPDFAC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				pdfAComplianceCheckFound = true;
			}
		}
		assertTrue(pdfAFormatCheckFound);
		assertTrue(pdfAComplianceCheckFound);
	}

	@Test
	public void pdfaWrongFormatTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_pdfa.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		MultiValuesConstraint valuesConstraint = new MultiValuesConstraint();
		valuesConstraint.setLevel(Level.FAIL);
		valuesConstraint.getId().add("PDF/A-2B");
		valuesConstraint.getId().add("PDF/A-2U");
		validationPolicy.getPDFAConstraints().setAcceptablePDFAProfiles(valuesConstraint);

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getPDFAConstraints().setPDFACompliant(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_DDAPDFAF_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.FAILED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);
		assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());

		XmlFC fc = signatureBBB.getFC();
		assertEquals(Indication.FAILED, fc.getConclusion().getIndication());

		boolean pdfAFormatCheckFound = false;
		boolean pdfAComplianceCheckFound = false;
		for (XmlConstraint constraint : fc.getConstraint()) {
			if (MessageTag.BBB_FC_DDAPDFAF.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_FC_DDAPDFAF_ANS.getId(), constraint.getError().getKey());
				pdfAFormatCheckFound = true;
			} else if (MessageTag.BBB_FC_IDPDFAC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				pdfAComplianceCheckFound = true;
			}
		}
		assertTrue(pdfAFormatCheckFound);
		assertFalse(pdfAComplianceCheckFound);
	}

	@Test
	public void pdfaInvalidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_pdfa.xml"));
		assertNotNull(xmlDiagnosticData);

		xmlDiagnosticData.getPDFAInfo().setCompliant(false);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		MultiValuesConstraint valuesConstraint = new MultiValuesConstraint();
		valuesConstraint.setLevel(Level.FAIL);
		valuesConstraint.getId().add("PDF/A-2A");
		valuesConstraint.getId().add("PDF/A-2B");
		valuesConstraint.getId().add("PDF/A-2U");
		validationPolicy.getPDFAConstraints().setAcceptablePDFAProfiles(valuesConstraint);

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getPDFAConstraints().setPDFACompliant(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_IDPDFAC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.FAILED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);
		assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());

		XmlFC fc = signatureBBB.getFC();
		assertEquals(Indication.FAILED, fc.getConclusion().getIndication());

		boolean pdfAFormatCheckFound = false;
		boolean pdfAComplianceCheckFound = false;
		for (XmlConstraint constraint : fc.getConstraint()) {
			if (MessageTag.BBB_FC_DDAPDFAF.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				pdfAFormatCheckFound = true;
			} else if (MessageTag.BBB_FC_IDPDFAC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_FC_IDPDFAC_ANS.getId(), constraint.getError().getKey());
				pdfAComplianceCheckFound = true;
			}
		}
		assertTrue(pdfAFormatCheckFound);
		assertTrue(pdfAComplianceCheckFound);
	}

	@Test
	public void pdfaValidIndependentTstTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_tst_pdfa_invalid.xml"));
		assertNotNull(xmlDiagnosticData);

		xmlDiagnosticData.getPDFAInfo().setCompliant(true);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getPDFAConstraints().setPDFACompliant(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstTimestampId()));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstTimestampId())));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(simpleReport.getFirstTimestampId()));

		XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstTimestampId());
		assertNotNull(tstBBB);
		assertEquals(Indication.PASSED, tstBBB.getConclusion().getIndication());

		XmlFC fc = tstBBB.getFC();
		assertEquals(Indication.PASSED, fc.getConclusion().getIndication());

		boolean pdfAComplianceCheckFound = false;
		for (XmlConstraint constraint : fc.getConstraint()) {
			assertEquals(XmlStatus.OK, constraint.getStatus());
			if (MessageTag.BBB_FC_IDPDFAC.getId().equals(constraint.getName().getKey())) {
				pdfAComplianceCheckFound = true;
			}
		}
		assertTrue(pdfAComplianceCheckFound);
	}

	@Test
	public void pdfaInvalidIndependentTstTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_tst_pdfa_invalid.xml"));
		assertNotNull(xmlDiagnosticData);

		xmlDiagnosticData.getPDFAInfo().setCompliant(false);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getPDFAConstraints().setPDFACompliant(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstTimestampId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstTimestampId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstTimestampId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_IDPDFAC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.FAILED, detailedReport.getBasicTimestampValidationIndication(simpleReport.getFirstTimestampId()));
		assertEquals(SubIndication.FORMAT_FAILURE, detailedReport.getBasicTimestampValidationSubIndication(simpleReport.getFirstTimestampId()));

		XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstTimestampId());
		assertNotNull(tstBBB);
		assertEquals(Indication.FAILED, tstBBB.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, tstBBB.getConclusion().getSubIndication());

		XmlFC fc = tstBBB.getFC();
		assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());

		boolean pdfAComplianceCheckFound = false;
		for (XmlConstraint constraint : fc.getConstraint()) {
			if (MessageTag.BBB_FC_IDPDFAC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_FC_IDPDFAC_ANS.getId(), constraint.getError().getKey());
				pdfAComplianceCheckFound = true;
			}
		}
		assertTrue(pdfAComplianceCheckFound);
	}

	@Test
	public void pdfaInvalidEnclosedTstWithUndefinedChangesWarnTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_pades_lta_mod_tst.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlPDFAInfo xmlPDFAInfo = new XmlPDFAInfo();
		xmlPDFAInfo.setCompliant(false);
		xmlDiagnosticData.setPDFAInfo(xmlPDFAInfo);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getPDFAConstraints().setPDFACompliant(levelConstraint);

		levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		validationPolicy.getTimestampConstraints().getBasicSignatureConstraints().setUndefinedChanges(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		DetailedReport detailedReport = reports.getDetailedReport();

		boolean sigTstFound = false;
		boolean arcTstFound = false;
		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp : signatureTimestamps) {
			assertEquals(Indication.PASSED, simpleReport.getIndication(timestamp.getId()));

			XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestamp.getId());
			assertNotNull(tstBBB);
			assertEquals(Indication.PASSED, tstBBB.getConclusion().getIndication());

			if (tstBBB.getFC() == null) {
				assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(timestamp.getId())));
				assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(timestamp.getId())));
				sigTstFound = true;

			} else {
				assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(timestamp.getId())));
				assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(timestamp.getId()),
						i18nProvider.getMessage(MessageTag.BBB_FC_DSCNUOM_ANS)));

				XmlFC fc = tstBBB.getFC();
				assertEquals(Indication.PASSED, fc.getConclusion().getIndication());

				boolean pdfAComplianceCheckFound = false;
				boolean undefinedChangesFound = false;
				for (XmlConstraint constraint : fc.getConstraint()) {
					if (MessageTag.BBB_FC_IDPDFAC.getId().equals(constraint.getName().getKey())) {
						pdfAComplianceCheckFound = true;

					} else if (MessageTag.BBB_FC_DSCNUOM.getId().equals(constraint.getName().getKey())) {
						assertEquals(XmlStatus.WARNING, constraint.getStatus());
						assertEquals(MessageTag.BBB_FC_DSCNUOM_ANS.getId(), constraint.getWarning().getKey());
						undefinedChangesFound = true;

					} else {
						assertEquals(XmlStatus.OK, constraint.getStatus());
					}
				}
				assertFalse(pdfAComplianceCheckFound);
				assertTrue(undefinedChangesFound);
				arcTstFound = true;
			}
		}
		assertTrue(sigTstFound);
		assertTrue(arcTstFound);
	}

	@Test
	public void pdfSignatureDictionaryInvalidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_pdfa.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);
		xmlSignature.getPDFRevision().getPDFSignatureDictionary().setConsistent(false);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setPdfSignatureDictionary(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_ISDC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.FAILED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);
		assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, signatureBBB.getConclusion().getSubIndication());

		XmlFC fc = signatureBBB.getFC();
		assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());

		boolean signDictCheckFound = false;
		for (XmlConstraint constraint : fc.getConstraint()) {
			if (MessageTag.BBB_FC_ISDC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_FC_ISDC_ANS.getId(), constraint.getError().getKey());
				signDictCheckFound = true;
			}
		}
		assertTrue(signDictCheckFound);
	}

	@Test
	public void signCertKeyUsageValidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add(KeyUsageBit.NON_REPUDIATION.getValue());
		multiValuesConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setKeyUsage(multiValuesConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);
		assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());

		assertEquals(3, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(0);
		assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

		boolean keyCertCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			assertEquals(XmlStatus.OK, constraint.getStatus());
			if (MessageTag.BBB_XCV_ISCGKU.getId().equals(constraint.getName().getKey())) {
				keyCertCheckFound = true;
			}
		}
		assertTrue(keyCertCheckFound);
	}

	@Test
	public void signCertKeyUsageInvalidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add(KeyUsageBit.DIGITAL_SIGNATURE.getValue());
		multiValuesConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setKeyUsage(multiValuesConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGKU_ANS, MessageTag.SIGNING_CERTIFICATE, MessageTag.SIGNATURE)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);
		assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, signatureBBB.getConclusion().getSubIndication());

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, xcv.getConclusion().getSubIndication());

		assertEquals(3, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(0);
		assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, subXCV.getConclusion().getSubIndication());

		boolean keyCertCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_ISCGKU.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_ISCGKU_ANS.getId(), constraint.getError().getKey());
				keyCertCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(keyCertCheckFound);
	}

	@Test
	public void caCertKeyUsageInvalidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlSigningCertificate caCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate()
				.getCertificate().getSigningCertificate();
		CertificateWrapper certificateWrapper = new CertificateWrapper(caCertificate.getCertificate());
		certificateWrapper.getKeyUsages().clear();

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add(KeyUsageBit.KEY_CERT_SIGN.getValue());
		multiValuesConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getCACertificate().setKeyUsage(multiValuesConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGKU_ANS, MessageTag.CA_CERTIFICATE, MessageTag.SIGNATURE)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);
		assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, signatureBBB.getConclusion().getSubIndication());

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

		assertEquals(3, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(1);
		assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

		boolean keyCertCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_ISCGKU.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_ISCGKU_ANS.getId(), constraint.getError().getKey());
				keyCertCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(keyCertCheckFound);
	}

	@Test
	public void signCertExtendedKeyUsageValidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		String timestampId = xmlDiagnosticData.getUsedTimestamps().get(0).getId();

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add(ExtendedKeyUsage.TIMESTAMPING.getDescription());
		multiValuesConstraint.setLevel(Level.FAIL);
		validationPolicy.getTimestampConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setExtendedKeyUsage(multiValuesConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.PASSED, simpleReport.getIndication(timestampId));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(timestampId)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(timestampId));

		XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestampId);
		assertNotNull(tstBBB);
		assertEquals(Indication.PASSED, tstBBB.getConclusion().getIndication());

		XmlXCV xcv = tstBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());

		assertEquals(2, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(0);
		assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

		boolean extendedKeyCertCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			assertEquals(XmlStatus.OK, constraint.getStatus());
			if (MessageTag.BBB_XCV_ISCGEKU.getId().equals(constraint.getName().getKey())) {
				extendedKeyCertCheckFound = true;
			}
		}
		assertTrue(extendedKeyCertCheckFound);
	}

	@Test
	public void signCertExtendedKeyUsageInvalidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlTimestamp xmlTimestamp = xmlDiagnosticData.getUsedTimestamps().get(0);
		CertificateWrapper certificateWrapper = new CertificateWrapper(xmlTimestamp.getSigningCertificate().getCertificate());
		certificateWrapper.getExtendedKeyUsages().clear();

		String timestampId = xmlTimestamp.getId();

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
		multiValuesConstraint.getId().add(ExtendedKeyUsage.TIMESTAMPING.getDescription());
		multiValuesConstraint.setLevel(Level.FAIL);
		validationPolicy.getTimestampConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setExtendedKeyUsage(multiValuesConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(timestampId));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(timestampId));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(timestampId),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGEKU_ANS, MessageTag.SIGNING_CERTIFICATE, MessageTag.TIMESTAMP)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(timestampId));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, detailedReport.getBasicTimestampValidationSubIndication(timestampId));

		XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestampId);
		assertNotNull(tstBBB);
		assertEquals(Indication.INDETERMINATE, tstBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, tstBBB.getConclusion().getSubIndication());

		XmlXCV xcv = tstBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, xcv.getConclusion().getSubIndication());

		assertEquals(2, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(0);
		assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, subXCV.getConclusion().getSubIndication());

		boolean extendedKeyCertCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_ISCGEKU.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_ISCGEKU_ANS.getId(), constraint.getError().getKey());
				extendedKeyCertCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(extendedKeyCertCheckFound);
	}

	@Test
	public void unknownRevocationTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_unknown_revocation.xml"));
		assertNotNull(xmlDiagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCUKN_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(sigBBB);

		XmlXCV xcv = sigBBB.getXCV();
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(2, subXCVs.size());

		XmlSubXCV subXCV = subXCVs.get(0);
		assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

		boolean acceptableRevocationCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getError().getKey());
				acceptableRevocationCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(acceptableRevocationCheckFound);

		XmlCRS crs = subXCV.getCRS();
		assertEquals(Indication.INDETERMINATE, crs.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, crs.getConclusion().getSubIndication());

		List<XmlRAC> racs = crs.getRAC();
		assertEquals(1, racs.size());

		XmlRAC xmlRAC = racs.get(0);
		assertEquals(Indication.INDETERMINATE, xmlRAC.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlRAC.getConclusion().getSubIndication());

		boolean revocationStatusKnownCheckFound = false;
		for (XmlConstraint constraint : xmlRAC.getConstraint()) {
			if (MessageTag.BBB_XCV_ISCUKN.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_ISCUKN_ANS.getId(), constraint.getError().getKey());
				revocationStatusKnownCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(revocationStatusKnownCheckFound);
	}

	@Test
	public void noExtendedKeyUsageTimestampingTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data-lta.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlTimestamp xmlTimestamp = xmlDiagnosticData.getUsedTimestamps().get(0);
		CertificateWrapper certificateWrapper = new CertificateWrapper(xmlTimestamp.getSigningCertificate().getCertificate());
		certificateWrapper.getExtendedKeyUsages().clear();

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		MultiValuesConstraint validationConstraint = new MultiValuesConstraint();
		validationConstraint.setLevel(Level.FAIL);
		validationConstraint.getId().add("timeStamping");
		validationPolicy.getTimestampConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setExtendedKeyUsage(validationConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(xmlTimestamp.getId()));
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, detailedReport.getBasicTimestampValidationSubIndication(xmlTimestamp.getId()));

		XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
		assertNotNull(timestampBBB);
		XmlXCV xcv = timestampBBB.getXCV();
		assertNotNull(xcv);

		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(2, subXCVs.size());

		XmlSubXCV xmlSubXCV = subXCVs.get(0);
		boolean extendedKeyUsageCheckFound = false;
		for (XmlConstraint constraint : xmlSubXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_ISCGEKU.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_ISCGEKU_ANS.getId(), constraint.getError().getKey());
				extendedKeyUsageCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(extendedKeyUsageCheckFound);

		SimpleReport simpleReport = reports.getSimpleReport();
		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		assertEquals(2, signatureTimestamps.size());

		eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp = signatureTimestamps.get(0);
		assertEquals(Indication.INDETERMINATE, timestamp.getIndication());
		assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, timestamp.getSubIndication());
		assertTrue(checkMessageValuePresence(convertMessages(timestamp.getAdESValidationDetails().getError()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGEKU_ANS, MessageTag.SIGNING_CERTIFICATE, MessageTag.TIMESTAMP)));

	}

	@Test
	public void fakeCAFailTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_fake_ca.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getCACertificate().setCA(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ICAC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, sigBBB.getConclusion().getSubIndication());

		XmlXCV xcv = sigBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

		assertEquals(3, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(1);
		assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

		boolean caCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_ICAC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_ICAC_ANS.getId(), constraint.getError().getKey());
				caCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(caCheckFound);
	}

	@Test
	public void maxPathLengthFailTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_fake_ca.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getCACertificate().setCA(levelConstraint);

		levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getCACertificate().setMaxPathLength(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ICPDV_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ICAC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, sigBBB.getConclusion().getSubIndication());

		XmlXCV xcv = sigBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

		assertEquals(3, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(1);
		assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

		boolean caCheckFound = false;
		boolean maxPathLengthCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_ICAC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_ICAC_ANS.getId(), constraint.getWarning().getKey());
				caCheckFound = true;
			} else if (MessageTag.BBB_XCV_ICPDV.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_ICPDV_ANS.getId(), constraint.getError().getKey());
				maxPathLengthCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(caCheckFound);
		assertTrue(maxPathLengthCheckFound);
	}

	@Test
	public void ocspWithWrongResponderIdTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_wrong_responderid.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getRevocationConstraints().setOCSPResponderIdMatch(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_REVOC_RESPID_MATCH_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, sigBBB.getConclusion().getSubIndication());

		XmlXCV xcv = sigBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

		assertEquals(2, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(0);
		assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

		boolean acceptableRevocDataCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getError().getKey());
				acceptableRevocDataCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(acceptableRevocDataCheckFound);

		XmlCRS crs = subXCV.getCRS();
		assertNotNull(crs);
		assertEquals(Indication.INDETERMINATE, crs.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, crs.getConclusion().getSubIndication());

		boolean revocAcceptanceCheckFound = false;
		acceptableRevocDataCheckFound = false;
		for (XmlConstraint constraint : crs.getConstraint()) {
			if (MessageTag.BBB_XCV_RAC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_RAC_ANS.getId(), constraint.getWarning().getKey());
				revocAcceptanceCheckFound = true;
			} else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), constraint.getError().getKey());
				acceptableRevocDataCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(revocAcceptanceCheckFound);
		assertTrue(acceptableRevocDataCheckFound);

		List<XmlRAC> racs = crs.getRAC();
		assertEquals(1, racs.size());

		XmlRAC xmlRAC = racs.get(0);
		assertEquals(Indication.INDETERMINATE, xmlRAC.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlRAC.getConclusion().getSubIndication());

		boolean responderIdCheckFound = false;
		for (XmlConstraint constraint : xmlRAC.getConstraint()) {
			if (MessageTag.BBB_XCV_REVOC_RESPID_MATCH.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_REVOC_RESPID_MATCH_ANS.getId(), constraint.getError().getKey());
				responderIdCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(responderIdCheckFound);
	}

	@Test
	public void ocspWithWrongResponderIdWarnTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_wrong_responderid.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.WARN);
		validationPolicy.getRevocationConstraints().setOCSPResponderIdMatch(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_REVOC_RESPID_MATCH_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

		XmlXCV xcv = sigBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());

		assertEquals(2, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(0);
		assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

		XmlCRS crs = subXCV.getCRS();
		assertNotNull(crs);
		assertEquals(Indication.PASSED, crs.getConclusion().getIndication());

		List<XmlRAC> racs = crs.getRAC();
		assertEquals(1, racs.size());

		XmlRAC xmlRAC = racs.get(0);
		assertEquals(Indication.PASSED, xmlRAC.getConclusion().getIndication());

		boolean responderIdCheckFound = false;
		for (XmlConstraint constraint : xmlRAC.getConstraint()) {
			if (MessageTag.BBB_XCV_REVOC_RESPID_MATCH.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_REVOC_RESPID_MATCH_ANS.getId(), constraint.getWarning().getKey());
				responderIdCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(responderIdCheckFound);
	}

	@Test
	public void forbiddenCertificateExtensionTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate xmlCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
		XmlIdPkixOcspNoCheck ocspNoCheck = new XmlIdPkixOcspNoCheck();
		ocspNoCheck.setOID(CertificateExtensionEnum.OCSP_NOCHECK.getOid());
		ocspNoCheck.setPresent(true);
		xmlCertificate.getCertificateExtensions().add(ocspNoCheck);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		MultiValuesConstraint levelConstraint = new MultiValuesConstraint();
		levelConstraint.setLevel(Level.FAIL);
		levelConstraint.getId().add(CertificateExtensionEnum.OCSP_NOCHECK.getOid());
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setForbiddenExtensions(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_DCCFCE_ANS, Arrays.asList(CertificateExtensionEnum.OCSP_NOCHECK.getOid()))));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, sigBBB.getConclusion().getSubIndication());

		XmlXCV xcv = sigBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

		assertEquals(3, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(0);
		assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

		boolean forbiddenExtensionCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_DCCFCE.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_DCCFCE_ANS.getId(), constraint.getError().getKey());
				forbiddenExtensionCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(forbiddenExtensionCheckFound);
	}

	@Test
	public void forbiddenCertificateExtensionWarnTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate xmlCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
		XmlIdPkixOcspNoCheck ocspNoCheck = new XmlIdPkixOcspNoCheck();
		ocspNoCheck.setOID(CertificateExtensionEnum.OCSP_NOCHECK.getOid());
		ocspNoCheck.setPresent(true);
		xmlCertificate.getCertificateExtensions().add(ocspNoCheck);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		MultiValuesConstraint levelConstraint = new MultiValuesConstraint();
		levelConstraint.setLevel(Level.WARN);
		levelConstraint.getId().add(CertificateExtensionEnum.OCSP_NOCHECK.getOid());
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setForbiddenExtensions(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_DCCFCE_ANS, Arrays.asList(CertificateExtensionEnum.OCSP_NOCHECK.getOid()))));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

		XmlXCV xcv = sigBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());

		assertEquals(3, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(0);
		assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

		boolean forbiddenExtensionCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_DCCFCE.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_DCCFCE_ANS.getId(), constraint.getWarning().getKey());
				forbiddenExtensionCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(forbiddenExtensionCheckFound);
	}

	@Test
	public void supportedCriticalCertificateExtensionsTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate xmlCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
		XmlKeyUsages keyUsages = new XmlKeyUsages();
		keyUsages.setOID(CertificateExtensionEnum.KEY_USAGE.getOid());
		keyUsages.setCritical(true);
		keyUsages.getKeyUsageBit().add(KeyUsageBit.NON_REPUDIATION);
		xmlCertificate.getCertificateExtensions().add(keyUsages);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		MultiValuesConstraint levelConstraint = new MultiValuesConstraint();
		levelConstraint.setLevel(Level.FAIL);
		levelConstraint.getId().add(CertificateExtensionEnum.KEY_USAGE.getOid());
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setSupportedCriticalExtensions(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_DCCUCE_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

		XmlXCV xcv = sigBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());

		assertEquals(3, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(0);
		assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

		boolean supportedExtensionsCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			assertEquals(XmlStatus.OK, constraint.getStatus());
			if (MessageTag.BBB_XCV_DCCUCE.getId().equals(constraint.getName().getKey())) {
				supportedExtensionsCheckFound = true;
			}
		}
		assertTrue(supportedExtensionsCheckFound);
	}

	@Test
	public void supportedCriticalCertificateExtensionsInvalidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate xmlCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
		for (XmlCertificateExtension certificateExtension : xmlCertificate.getCertificateExtensions()) {
			if (certificateExtension instanceof XmlKeyUsages) {
				certificateExtension.setCritical(true);
			}
		}

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		MultiValuesConstraint levelConstraint = new MultiValuesConstraint();
		levelConstraint.setLevel(Level.FAIL);
		levelConstraint.getId().add(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setSupportedCriticalExtensions(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_DCCUCE_ANS, Arrays.asList(CertificateExtensionEnum.KEY_USAGE.getOid()))));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, sigBBB.getConclusion().getSubIndication());

		XmlXCV xcv = sigBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

		assertEquals(3, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(0);
		assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

		boolean supportedExtensionsCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_DCCUCE.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_DCCUCE_ANS.getId(), constraint.getError().getKey());
				supportedExtensionsCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(supportedExtensionsCheckFound);
	}

	@Test
	public void policyTreeValidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_policy_constraints.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setPolicyTree(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

		XmlXCV xcv = sigBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());

		assertEquals(2, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(0);
		assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

		boolean policyTreeCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			assertEquals(XmlStatus.OK, constraint.getStatus());
			if (MessageTag.BBB_XCV_ICPTV.getId().equals(constraint.getName().getKey())) {
				policyTreeCheckFound = true;
			}
		}
		assertTrue(policyTreeCheckFound);
	}

	@Test
	public void policyTreeInvalidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_policy_constraints.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate xmlCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
		for (XmlCertificateExtension certificateExtension : xmlCertificate.getCertificateExtensions()) {
			if (certificateExtension instanceof XmlCertificatePolicies) {
				XmlCertificatePolicies xmlCertificatePolicies = (XmlCertificatePolicies) certificateExtension;
				xmlCertificatePolicies.getCertificatePolicy().get(0).setValue("1.2.3.4.5");
				xmlCertificatePolicies.getCertificatePolicy().get(1).setValue("6.7.8.9.0");
			}
		}

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setPolicyTree(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ICPTV_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, sigBBB.getConclusion().getSubIndication());

		XmlXCV xcv = sigBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

		assertEquals(2, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(0);
		assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

		boolean policyTreeCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_ICPTV.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_ICPTV_ANS.getId(), constraint.getError().getKey());
				policyTreeCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(policyTreeCheckFound);
	}

	@Test
	public void nameConstraintsValidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_name_constraints.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setNameConstraints(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

		XmlXCV xcv = sigBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());

		assertEquals(2, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(0);
		assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

		boolean nameConstraintsCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			assertEquals(XmlStatus.OK, constraint.getStatus());
			if (MessageTag.BBB_XCV_DCSBSINC.getId().equals(constraint.getName().getKey())) {
				nameConstraintsCheckFound = true;
			}
		}
		assertTrue(nameConstraintsCheckFound);
	}

	@Test
	public void nameConstraintsInvalidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_name_constraints.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate xmlCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
		xmlCertificate.getSubjectDistinguishedName().clear();
		XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
		xmlDistinguishedName.setFormat("RFC2253");
		xmlDistinguishedName.setValue("C=SK,L=Bratislava,2.5.4.5=#534b2d353033343932130e4e54523837,OU=sep,O=Mini,CN=SR");
		xmlCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setNameConstraints(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_DCSBSINC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, sigBBB.getConclusion().getSubIndication());

		XmlXCV xcv = sigBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

		assertEquals(2, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(0);
		assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

		boolean nameConstraintsCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_DCSBSINC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_DCSBSINC_ANS.getId(), constraint.getError().getKey());
				nameConstraintsCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(nameConstraintsCheckFound);
	}

	@Test
	public void nameConstraintsSubjectAltNameInvalidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_name_constraints.xml"));
		assertNotNull(xmlDiagnosticData);

		XmlCertificate xmlCertificate = xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
		for (XmlCertificateExtension certificateExtension : xmlCertificate.getCertificateExtensions()) {
			if (CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid().equals(certificateExtension.getOID())) {
				XmlSubjectAlternativeNames subjectAlternativeNames = (XmlSubjectAlternativeNames) certificateExtension;
				subjectAlternativeNames.getSubjectAlternativeName().get(0).setValue("C=SK,L=Bratislava,2.5.4.5=#534b2d353033343932130e4e54523837,OU=sep,O=Mini,CN=SR");
			}
		}

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setNameConstraints(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_DCSBSINC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, sigBBB.getConclusion().getSubIndication());

		XmlXCV xcv = sigBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

		assertEquals(2, xcv.getSubXCV().size());
		XmlSubXCV subXCV = xcv.getSubXCV().get(0);
		assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());

		boolean nameConstraintsCheckFound = false;
		for (XmlConstraint constraint : subXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_DCSBSINC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_DCSBSINC_ANS.getId(), constraint.getError().getKey());
				nameConstraintsCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(nameConstraintsCheckFound);
	}

	@Test
	public void signatureTimeStampPresentTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data-lta.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getUnsignedAttributes().setSignatureTimeStamp(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

		XmlSAV sav = sigBBB.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.PASSED, sav.getConclusion().getIndication());

		boolean tstPresentCheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			assertEquals(XmlStatus.OK, constraint.getStatus());
			if (MessageTag.BBB_SAV_IUQPSTSP.getId().equals(constraint.getName().getKey())) {
				tstPresentCheckFound = true;
			}
		}
		assertTrue(tstPresentCheckFound);

		xmlDiagnosticData.getUsedTimestamps().get(0).setType(TimestampType.CONTENT_TIMESTAMP);

		reports = executor.execute();
		assertNotNull(reports);

		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_SAV_IUQPSTSP_ANS)));

		detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sigBBB.getConclusion().getSubIndication());

		sav = sigBBB.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

		tstPresentCheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			if (MessageTag.BBB_SAV_IUQPSTSP.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_SAV_IUQPSTSP_ANS.getId(), constraint.getError().getKey());
				tstPresentCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(tstPresentCheckFound);
	}

	@Test
	public void validationDataTimeStampPresentTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data-lta.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getUnsignedAttributes().setValidationDataTimeStamp(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_SAV_IUQPVDTSP_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sigBBB.getConclusion().getSubIndication());

		XmlSAV sav = sigBBB.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

		boolean tstPresentCheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			if (MessageTag.BBB_SAV_IUQPVDTSP.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_SAV_IUQPVDTSP_ANS.getId(), constraint.getError().getKey());
				tstPresentCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(tstPresentCheckFound);

		xmlDiagnosticData.getUsedTimestamps().get(1).setType(TimestampType.VALIDATION_DATA_TIMESTAMP);

		reports = executor.execute();
		assertNotNull(reports);

		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

		sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

		sav = sigBBB.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.PASSED, sav.getConclusion().getIndication());

		tstPresentCheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			assertEquals(XmlStatus.OK, constraint.getStatus());
			if (MessageTag.BBB_SAV_IUQPVDTSP.getId().equals(constraint.getName().getKey())) {
				tstPresentCheckFound = true;
			}
		}
		assertTrue(tstPresentCheckFound);
	}

	@Test
	public void validationDataRefsOnlyTimeStampPresentTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data-lta.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getUnsignedAttributes().setValidationDataRefsOnlyTimeStamp(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_SAV_IUQPVDROTSP_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sigBBB.getConclusion().getSubIndication());

		XmlSAV sav = sigBBB.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

		boolean tstPresentCheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			if (MessageTag.BBB_SAV_IUQPVDROTSP.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_SAV_IUQPVDROTSP_ANS.getId(), constraint.getError().getKey());
				tstPresentCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(tstPresentCheckFound);

		xmlDiagnosticData.getUsedTimestamps().get(1).setType(TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);

		reports = executor.execute();
		assertNotNull(reports);

		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

		sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

		sav = sigBBB.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.PASSED, sav.getConclusion().getIndication());

		tstPresentCheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			assertEquals(XmlStatus.OK, constraint.getStatus());
			if (MessageTag.BBB_SAV_IUQPVDROTSP.getId().equals(constraint.getName().getKey())) {
				tstPresentCheckFound = true;
			}
		}
		assertTrue(tstPresentCheckFound);
	}

	@Test
	public void archiveTimeStampPresentTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data-lta.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getUnsignedAttributes().setArchiveTimeStamp(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

		XmlSAV sav = sigBBB.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.PASSED, sav.getConclusion().getIndication());

		boolean tstPresentCheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			assertEquals(XmlStatus.OK, constraint.getStatus());
			if (MessageTag.BBB_SAV_IUQPATSP.getId().equals(constraint.getName().getKey())) {
				tstPresentCheckFound = true;
			}
		}
		assertTrue(tstPresentCheckFound);

		xmlDiagnosticData.getUsedTimestamps().get(1).setType(TimestampType.VALIDATION_DATA_TIMESTAMP);

		reports = executor.execute();
		assertNotNull(reports);

		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_SAV_IUQPATSP_ANS)));

		detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sigBBB.getConclusion().getSubIndication());

		sav = sigBBB.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

		tstPresentCheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			if (MessageTag.BBB_SAV_IUQPATSP.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_SAV_IUQPATSP_ANS.getId(), constraint.getError().getKey());
				tstPresentCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(tstPresentCheckFound);
	}

	@Test
	public void documentTimeStampPresentTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_pades_lta_mod_tst.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getUnsignedAttributes().setDocumentTimeStamp(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

		XmlSAV sav = sigBBB.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.PASSED, sav.getConclusion().getIndication());

		boolean tstPresentCheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			assertEquals(XmlStatus.OK, constraint.getStatus());
			if (MessageTag.BBB_SAV_IDTSP.getId().equals(constraint.getName().getKey())) {
				tstPresentCheckFound = true;
			}
		}
		assertTrue(tstPresentCheckFound);

		xmlDiagnosticData.getUsedTimestamps().get(1).setType(TimestampType.VRI_TIMESTAMP);

		reports = executor.execute();
		assertNotNull(reports);

		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_SAV_IDTSP_ANS)));

		detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		sigBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstSignatureId());
		assertNotNull(sigBBB);
		assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sigBBB.getConclusion().getSubIndication());

		sav = sigBBB.getSAV();
		assertNotNull(sav);
		assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());

		tstPresentCheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			if (MessageTag.BBB_SAV_IDTSP.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_SAV_IDTSP_ANS.getId(), constraint.getError().getKey());
				tstPresentCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(tstPresentCheckFound);

	}

	@Test
	public void expiredSigAndTstTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/dss-2070.xml"));
		assertNotNull(xmlDiagnosticData);

		Calendar calendar = Calendar.getInstance();
		calendar.set(Calendar.YEAR, 2022);
		xmlDiagnosticData.setValidationDate(calendar.getTime());

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.PSV_IPSVC_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.PSV_IPTVC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = detailedReport.getXmlTimestampById(xmlDiagnosticData.getUsedTimestamps().get(0).getId());
		XmlValidationProcessBasicTimestamp basicValidationProcessTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
		assertEquals(Indication.INDETERMINATE, basicValidationProcessTimestamp.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, basicValidationProcessTimestamp.getConclusion().getSubIndication());

		XmlValidationProcessArchivalDataTimestamp validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
		assertEquals(Indication.INDETERMINATE, validationProcessArchivalDataTimestamp.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessArchivalDataTimestamp.getConclusion().getSubIndication());

		boolean basicTstAllowedValidationFound = false;
		boolean basicValidationCheckFound = false;
		boolean tstPSVFound = false;
		for (XmlConstraint xmlConstraint : validationProcessArchivalDataTimestamp.getConstraint()) {
			if (MessageTag.ARCH_IRTVBBA.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				basicTstAllowedValidationFound = true;

			} else if (MessageTag.ADEST_IBSVPTC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
				assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), xmlConstraint.getWarning().getKey());
				basicValidationCheckFound = true;

			} else if (MessageTag.PSV_IPTVC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				assertEquals(MessageTag.PSV_IPTVC_ANS.getId(), xmlConstraint.getError().getKey());
				tstPSVFound = true;

			} else {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
			}
		}
		assertTrue(basicTstAllowedValidationFound);
		assertTrue(basicValidationCheckFound);
		assertTrue(tstPSVFound);

		XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlDiagnosticData.getUsedTimestamps().get(0).getId());
		assertNotNull(tstBBB);

		XmlPSV psv = tstBBB.getPSV();
		assertEquals(Indication.INDETERMINATE, psv.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, psv.getConclusion().getSubIndication());

		XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
		assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessArchivalData.getConclusion().getSubIndication());

		boolean tstAllowedValidationFound = false;
		boolean sigPSVFound = false;
		for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
			if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
				assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getWarning().getKey());
				tstAllowedValidationFound = true;

			} else if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				assertEquals(MessageTag.PSV_IPSVC_ANS.getId(), xmlConstraint.getError().getKey());
				sigPSVFound = true;

			} else {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
			}
		}
		assertTrue(tstAllowedValidationFound);
		assertTrue(sigPSVFound);
	}

	@Test
	public void expiredSigAndTstWithTstCheckWarnLevelTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/dss-2070.xml"));
		assertNotNull(xmlDiagnosticData);

		Calendar calendar = Calendar.getInstance();
		calendar.set(Calendar.YEAR, 2022);
		xmlDiagnosticData.setValidationDate(calendar.getTime());

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.WARN);
		validationPolicy.getTimestampConstraints().setTimestampValid(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.PSV_IPSVC_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(
				xmlDiagnosticData.getUsedTimestamps().get(0).getId()).getValidationProcessBasicTimestamp();
		assertEquals(Indication.INDETERMINATE, validationProcessTimestamp.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessTimestamp.getConclusion().getSubIndication());

		XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlDiagnosticData.getUsedTimestamps().get(0).getId());
		assertNotNull(tstBBB);

		XmlPSV psv = tstBBB.getPSV();
		assertEquals(Indication.INDETERMINATE, psv.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, psv.getConclusion().getSubIndication());

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
		assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessArchivalData.getConclusion().getSubIndication());

		boolean tstAllowedValidationFound = false;
		boolean sigPSVFound = false;
		for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
			if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
				assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getWarning().getKey());
				tstAllowedValidationFound = true;

			} else if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				assertEquals(MessageTag.PSV_IPSVC_ANS.getId(), xmlConstraint.getError().getKey());
				sigPSVFound = true;

			} else {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
			}
		}
		assertTrue(tstAllowedValidationFound);
		assertTrue(sigPSVFound);

		XmlValidationProcessArchivalDataTimestamp tstValidationProcessArchivalData = xmlSignature.getTimestamps().get(0).getValidationProcessArchivalDataTimestamp();
		assertEquals(Indication.INDETERMINATE, tstValidationProcessArchivalData.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, tstValidationProcessArchivalData.getConclusion().getSubIndication());

		boolean tstAllowedBasicValidationFound = false;
		boolean tstConclusiveBasicValidationFound = false;
		boolean tstPSVFound = false;

		List<XmlConstraint> constraints = tstValidationProcessArchivalData.getConstraint();
		for (XmlConstraint xmlConstraint : constraints) {
			if (MessageTag.ARCH_IRTVBBA.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				tstAllowedBasicValidationFound = true;

			} else if (MessageTag.ADEST_IBSVPTC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
				assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), xmlConstraint.getWarning().getKey());
				tstConclusiveBasicValidationFound = true;

			} else if (MessageTag.PSV_IPTVC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				assertEquals(MessageTag.PSV_IPTVC_ANS.getId(), xmlConstraint.getError().getKey());
				tstPSVFound = true;

			} else {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
			}
		}

		assertTrue(tstAllowedBasicValidationFound);
		assertTrue(tstConclusiveBasicValidationFound);
		assertTrue(tstPSVFound);
	}

	@Test
	public void sigWithFailedTstFailLevelTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data-lta.xml"));
		assertNotNull(xmlDiagnosticData);

		xmlDiagnosticData.getUsedTimestamps().get(0).getBasicSignature().setSignatureIntact(false);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		validationPolicy.getTimestampConstraints().setTimestampValid(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CRYPTO_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.PSV_IPSVC_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.PSV_IPTVC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

		XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(
				xmlDiagnosticData.getUsedTimestamps().get(0).getId()).getValidationProcessBasicTimestamp();
		assertEquals(Indication.FAILED, validationProcessTimestamp.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CRYPTO_FAILURE, validationProcessTimestamp.getConclusion().getSubIndication());

		XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlDiagnosticData.getUsedTimestamps().get(0).getId());
		assertNotNull(tstBBB);

		XmlPSV psv = tstBBB.getPSV();
		assertNull(psv);

		XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
		assertEquals(Indication.FAILED, validationProcessArchivalData.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CRYPTO_FAILURE, validationProcessArchivalData.getConclusion().getSubIndication());

		boolean tstAllowedValidationFound = false;
		for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
			if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
				if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
					assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getError().getKey());
					tstAllowedValidationFound = true;
				}
			} else {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
			}
		}
		assertTrue(tstAllowedValidationFound);
	}

	@Test
	public void tLevelTstFoundValidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data-lta.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getUnsignedAttributes().setTLevelTimeStamp(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_SAV_IVTTSTP_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.ARCH_IRTVBBA_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

		for (XmlTimestamp xmlTimestamp : xmlDiagnosticData.getUsedTimestamps()) {
			XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(xmlTimestamp.getId()).getValidationProcessBasicTimestamp();
			assertEquals(Indication.PASSED, validationProcessTimestamp.getConclusion().getIndication());
		}

		XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
		assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

		boolean tLevelCheckFound = false;
		for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
			if (MessageTag.BBB_SAV_IVTTSTP.getId().equals(xmlConstraint.getName().getKey())) {
				tLevelCheckFound = true;
			}
			assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
		}
		assertTrue(tLevelCheckFound);
	}

	@Test
	public void tLevelTstFoundInvalidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data-lta.xml"));
		assertNotNull(xmlDiagnosticData);

		xmlDiagnosticData.getUsedTimestamps().get(0).getBasicSignature().setSignatureIntact(false);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getUnsignedAttributes().setTLevelTimeStamp(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_SAV_IVTTSTP_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.ARCH_IRTVBBA_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

		boolean validTstFound = false;
		boolean invalidTstFound = false;
		for (XmlTimestamp xmlTimestamp : xmlDiagnosticData.getUsedTimestamps()) {
			XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(xmlTimestamp.getId()).getValidationProcessBasicTimestamp();
			if (Indication.PASSED == validationProcessTimestamp.getConclusion().getIndication()) {
				assertEquals(TimestampType.ARCHIVE_TIMESTAMP, xmlTimestamp.getType());
				validTstFound = true;
			} else if (Indication.FAILED == validationProcessTimestamp.getConclusion().getIndication()) {
				assertEquals(SubIndication.SIG_CRYPTO_FAILURE, validationProcessTimestamp.getConclusion().getSubIndication());
				assertEquals(TimestampType.SIGNATURE_TIMESTAMP, xmlTimestamp.getType());
				invalidTstFound = true;
			}
		}
		assertTrue(validTstFound);
		assertTrue(invalidTstFound);

		XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
		assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, validationProcessArchivalData.getConclusion().getSubIndication());

		boolean tstValidationCheckSuccessFound = false;
		boolean tstValidationCheckFailureFound = false;
		boolean tLevelCheckFound = false;
		for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
			if (MessageTag.BBB_SAV_IVTTSTP.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				assertEquals(MessageTag.BBB_SAV_IVTTSTP_ANS.getId(), xmlConstraint.getError().getKey());
				tLevelCheckFound = true;

			} else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
				if (XmlStatus.OK.equals(xmlConstraint.getStatus())) {
					tstValidationCheckSuccessFound = true;
				} else if (XmlStatus.WARNING.equals(xmlConstraint.getStatus())) {
					assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getWarning().getKey());
					tstValidationCheckFailureFound = true;
				}

			} else {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
			}

		}
		assertTrue(tstValidationCheckSuccessFound);
		assertTrue(tstValidationCheckFailureFound);
		assertTrue(tLevelCheckFound);
	}

	@Test
	public void ltaLevelTstFoundValidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data-lta.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getUnsignedAttributes().setLTALevelTimeStamp(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_SAV_IVLTATSTP_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.ARCH_IRTVBBA_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

		for (XmlTimestamp xmlTimestamp : xmlDiagnosticData.getUsedTimestamps()) {
			XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(xmlTimestamp.getId()).getValidationProcessBasicTimestamp();
			assertEquals(Indication.PASSED, validationProcessTimestamp.getConclusion().getIndication());
		}

		XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
		assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

		boolean ltaLevelCheckFound = false;
		for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
			if (MessageTag.BBB_SAV_IVLTATSTP.getId().equals(xmlConstraint.getName().getKey())) {
				ltaLevelCheckFound = true;
			}
			assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
		}
		assertTrue(ltaLevelCheckFound);
	}

	@Test
	public void ltaLevelTstFoundInvalidTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data-lta.xml"));
		assertNotNull(xmlDiagnosticData);

		xmlDiagnosticData.getUsedTimestamps().get(1).getBasicSignature().setSignatureIntact(false);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getUnsignedAttributes().setLTALevelTimeStamp(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_SAV_IVLTATSTP_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.ARCH_IRTVBBA_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

		boolean validTstFound = false;
		boolean invalidTstFound = false;
		for (XmlTimestamp xmlTimestamp : xmlDiagnosticData.getUsedTimestamps()) {
			XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(xmlTimestamp.getId()).getValidationProcessBasicTimestamp();
			if (Indication.PASSED == validationProcessTimestamp.getConclusion().getIndication()) {
				assertEquals(TimestampType.SIGNATURE_TIMESTAMP, xmlTimestamp.getType());
				validTstFound = true;
			} else if (Indication.FAILED == validationProcessTimestamp.getConclusion().getIndication()) {
				assertEquals(SubIndication.SIG_CRYPTO_FAILURE, validationProcessTimestamp.getConclusion().getSubIndication());
				assertEquals(TimestampType.ARCHIVE_TIMESTAMP, xmlTimestamp.getType());
				invalidTstFound = true;
			}
		}
		assertTrue(validTstFound);
		assertTrue(invalidTstFound);

		XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
		assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, validationProcessArchivalData.getConclusion().getSubIndication());

		boolean tstValidationCheckSuccessFound = false;
		boolean tstValidationCheckFailureFound = false;
		boolean ltaLevelCheckFound = false;
		for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
			if (MessageTag.BBB_SAV_IVLTATSTP.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				assertEquals(MessageTag.BBB_SAV_IVLTATSTP_ANS.getId(), xmlConstraint.getError().getKey());
				ltaLevelCheckFound = true;

			} else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
				if (XmlStatus.OK.equals(xmlConstraint.getStatus())) {
					tstValidationCheckSuccessFound = true;
				} else if (XmlStatus.WARNING.equals(xmlConstraint.getStatus())) {
					assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getWarning().getKey());
					tstValidationCheckFailureFound = true;
				}

			} else {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
			}

		}
		assertTrue(tstValidationCheckSuccessFound);
		assertTrue(tstValidationCheckFailureFound);
		assertTrue(ltaLevelCheckFound);
	}

	@Test
	public void asicValidIndependentTstTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_tst_asic.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		MultiValuesConstraint levelConstraint = new MultiValuesConstraint();
		levelConstraint.setLevel(Level.FAIL);
		levelConstraint.getId().add(ASiCContainerType.ASiC_E.toString());
		validationPolicy.getContainerConstraints().setAcceptableContainerTypes(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstTimestampId()));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstTimestampId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_IECTF_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(simpleReport.getFirstTimestampId()));

		XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstTimestampId());
		assertNotNull(tstBBB);
		assertEquals(Indication.PASSED, tstBBB.getConclusion().getIndication());

		XmlFC fc = tstBBB.getFC();
		assertEquals(Indication.PASSED, fc.getConclusion().getIndication());

		boolean containerCheckFound = false;
		for (XmlConstraint constraint : fc.getConstraint()) {
			if (MessageTag.BBB_FC_IECTF.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				containerCheckFound = true;
			}
		}
		assertTrue(containerCheckFound);
	}

	@Test
	public void asicInvalidIndependentTstTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_tst_asic.xml"));
		assertNotNull(xmlDiagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		MultiValuesConstraint levelConstraint = new MultiValuesConstraint();
		levelConstraint.setLevel(Level.FAIL);
		levelConstraint.getId().add(ASiCContainerType.ASiC_S.toString());
		validationPolicy.getContainerConstraints().setAcceptableContainerTypes(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstTimestampId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstTimestampId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstTimestampId()),
				i18nProvider.getMessage(MessageTag.BBB_FC_IECTF_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.FAILED, detailedReport.getBasicTimestampValidationIndication(simpleReport.getFirstTimestampId()));
		assertEquals(SubIndication.FORMAT_FAILURE, detailedReport.getBasicTimestampValidationSubIndication(simpleReport.getFirstTimestampId()));

		XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(simpleReport.getFirstTimestampId());
		assertNotNull(tstBBB);
		assertEquals(Indication.FAILED, tstBBB.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, tstBBB.getConclusion().getSubIndication());

		XmlFC fc = tstBBB.getFC();
		assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());

		boolean containerCheckFound = false;
		for (XmlConstraint constraint : fc.getConstraint()) {
			if (MessageTag.BBB_FC_IECTF.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_FC_IECTF_ANS.getId(), constraint.getError().getKey());
				containerCheckFound = true;
			}
		}
		assertTrue(containerCheckFound);
	}

	@Test
	public void notTrustedCertChainTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		for (XmlCertificate certificate : xmlDiagnosticData.getUsedCertificates()) {
			certificate.getSources().remove(CertificateSourceType.TRUSTED_STORE);
		}

		ValidationPolicy validationPolicy = loadDefaultPolicy();

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CCCBB_SIG_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.INDETERMINATE, bbb.getConclusion().getIndication());
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, bbb.getConclusion().getSubIndication());

		XmlXCV xcv = bbb.getXCV();
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, xcv.getConclusion().getSubIndication());

		boolean prospectiveCertChainCheckFound = false;
		for (XmlConstraint constraint : xcv.getConstraint()) {
			if (MessageTag.BBB_XCV_CCCBB.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_CCCBB_SIG_ANS.getId(), constraint.getError().getKey());
				prospectiveCertChainCheckFound = true;
			}
		}
		assertTrue(prospectiveCertChainCheckFound);
		assertTrue(Utils.isCollectionEmpty(xcv.getSubXCV()));
	}

	@Test
	public void notTrustedCertChainInformTest() throws Exception {
		XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(xmlDiagnosticData);

		for (XmlCertificate certificate : xmlDiagnosticData.getUsedCertificates()) {
			certificate.getSources().remove(CertificateSourceType.TRUSTED_STORE);
		}

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.INFORM);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setProspectiveCertificateChain(levelConstraint);
		validationPolicy.getRevocationConstraints().getBasicSignatureConstraints().setProspectiveCertificateChain(levelConstraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(xmlDiagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_CCCBB_SIG_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.PASSED, bbb.getConclusion().getIndication());

		XmlXCV xcv = bbb.getXCV();
		assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());

		boolean prospectiveCertChainCheckFound = false;
		for (XmlConstraint constraint : xcv.getConstraint()) {
			if (MessageTag.BBB_XCV_CCCBB.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.INFORMATION, constraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_CCCBB_SIG_ANS.getId(), constraint.getInfo().getKey());
				prospectiveCertChainCheckFound = true;
			}
		}
		assertTrue(prospectiveCertChainCheckFound);
		assertEquals(3, xcv.getSubXCV().size());
	}

	@Test
	public void issuerNameFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlCertificate certificate = diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
		certificate.getIssuerDistinguishedName().clear();

		XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
		xmlDistinguishedName.setFormat("CANONICAL");
		xmlDistinguishedName.setValue("c=lu,ou=pki-test,o=nowina solutions,cn=invalid-ca");
		certificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

		xmlDistinguishedName = new XmlDistinguishedName();
		xmlDistinguishedName.setFormat("RFC2253");
		xmlDistinguishedName.setValue("C=LU,OU=PKI-TEST,O=Nowina Solutions,CN=invalid-ca");
		certificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setIssuerName(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_DCIDNMSDNIC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(sigBBB);

		XmlXCV xcv = sigBBB.getXCV();
		assertNotNull(xcv);
		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(3, subXCVs.size());

		XmlSubXCV xmlSubXCV = subXCVs.get(0);
		boolean issuerNameCheckFound = false;
		for (XmlConstraint xmlConstraint : xmlSubXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_DCIDNMSDNIC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_DCIDNMSDNIC_ANS.getId(), xmlConstraint.getError().getKey());
				issuerNameCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
			}
		}
		assertTrue(issuerNameCheckFound);
	}

	@Test
	public void issuerNameWarnLevel() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);

		XmlCertificate certificate = diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
		certificate.getIssuerDistinguishedName().clear();

		XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
		xmlDistinguishedName.setFormat("CANONICAL");
		xmlDistinguishedName.setValue("c=lu,ou=pki-test,o=nowina solutions,cn=invalid-ca");
		certificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

		xmlDistinguishedName = new XmlDistinguishedName();
		xmlDistinguishedName.setFormat("RFC2253");
		xmlDistinguishedName.setValue("C=LU,OU=PKI-TEST,O=Nowina Solutions,CN=invalid-ca");
		certificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.WARN);
		validationPolicy.getSignatureConstraints().getBasicSignatureConstraints()
				.getSigningCertificate().setIssuerName(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_DCIDNMSDNIC_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_DCIDNMSDNIC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(sigBBB);

		XmlXCV xcv = sigBBB.getXCV();
		assertNotNull(xcv);
		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(3, subXCVs.size());

		XmlSubXCV xmlSubXCV = subXCVs.get(0);
		boolean issuerNameCheckFound = false;
		for (XmlConstraint xmlConstraint : xmlSubXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_DCIDNMSDNIC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
				assertEquals(MessageTag.BBB_XCV_DCIDNMSDNIC_ANS.getId(), xmlConstraint.getWarning().getKey());
				issuerNameCheckFound = true;
			} else {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
			}
		}
		assertTrue(issuerNameCheckFound);
	}

	@Test
	public void sigWithERValidationTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/er-validation/sig-with-er-valid.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		assertEquals(1, signatureTimestamps.size());
		assertEquals(Indication.PASSED, signatureTimestamps.get(0).getIndication());

		List<eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(simpleReport.getFirstSignatureId());
		assertEquals(1, signatureEvidenceRecords.size());
		assertEquals(Indication.PASSED, signatureEvidenceRecords.get(0).getIndication());

		XmlTimestamps timestamps = signatureEvidenceRecords.get(0).getTimestamps();
		assertNotNull(timestamps);
		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> evidenceRecordTimestamps = timestamps.getTimestamp();
		assertEquals(2, evidenceRecordTimestamps.size());
		for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp : evidenceRecordTimestamps) {
			assertEquals(Indication.PASSED, xmlTimestamp.getIndication());
		}

		DetailedReport detailedReport = reports.getDetailedReport();

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(signatureTimestamps.get(0).getId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

		assertEquals(Indication.PASSED, detailedReport.getArchiveDataTimestampValidationIndication(signatureTimestamps.get(0).getId()));

		int processedTimestampsCounter = 0;
		int skippedTimestampsCounter = 0;
		for (XmlTimestamp xmlTimestamp : diagnosticData.getUsedTimestamps()) {
			XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
			if (tstBBB != null) {
				++processedTimestampsCounter;
			} else {
				++skippedTimestampsCounter;
			}
		}
		assertEquals(3, processedTimestampsCounter);
		assertEquals(0, skippedTimestampsCounter);

		assertEquals(Indication.PASSED, detailedReport.getEvidenceRecordValidationIndication(signatureEvidenceRecords.get(0).getId()));

		eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord xmlEvidenceRecord = detailedReport.getXmlEvidenceRecordById(signatureEvidenceRecords.get(0).getId());
		assertEquals(Indication.PASSED, xmlEvidenceRecord.getConclusion().getIndication());

		XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
		assertEquals(Indication.PASSED, validationProcessEvidenceRecord.getConclusion().getIndication());

		int dataObjectFoundCheckCounter = 0;
		int dataObjectIntactCheckCounter = 0;
		int tstValidationConclusiveCheckCounter = 0;
		int cryptoConstraintsCheckCounter = 0;
		for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
			if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				++dataObjectFoundCheckCounter;
			} else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				++dataObjectIntactCheckCounter;
			} else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				++tstValidationConclusiveCheckCounter;
			} else if (MessageTag.ACCM.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				++cryptoConstraintsCheckCounter;
			}
		}
		assertEquals(1, dataObjectFoundCheckCounter);
		assertEquals(1, dataObjectIntactCheckCounter);
		assertEquals(2, tstValidationConclusiveCheckCounter);
		assertEquals(1, cryptoConstraintsCheckCounter);

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		
		XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
		assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());
		
		boolean evidenceRecordCheckFound = false;
		boolean ltLevelAcceptableCheckFound = false;
		boolean tstValidationCheckFound = false;
		boolean pastSignatureValidationCheckFound = false;
		for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
			if (MessageTag.ADEST_IRERVPC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				evidenceRecordCheckFound = true;
			} else if (MessageTag.ARCH_LTVV.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				ltLevelAcceptableCheckFound = true;
			} else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				tstValidationCheckFound = true;
			} else if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				pastSignatureValidationCheckFound = true;
			}
		}
		assertTrue(evidenceRecordCheckFound);
		assertTrue(ltLevelAcceptableCheckFound);
		assertTrue(tstValidationCheckFound);
		assertTrue(pastSignatureValidationCheckFound);
	}

	@Test
	public void sigWithBrokenERValidationTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/er-validation/sig-with-er-valid.xml"));
		assertNotNull(diagnosticData);

		XmlEvidenceRecord xmlEvidenceRecord = diagnosticData.getEvidenceRecords().get(0);
		xmlEvidenceRecord.getDigestMatchers().get(0).setDataIntact(false);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		assertEquals(1, signatureTimestamps.size());
		assertEquals(Indication.INDETERMINATE, signatureTimestamps.get(0).getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, signatureTimestamps.get(0).getSubIndication());

		List<eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(simpleReport.getFirstSignatureId());
		assertEquals(1, signatureEvidenceRecords.size());
		assertEquals(Indication.FAILED, signatureEvidenceRecords.get(0).getIndication());
		assertEquals(SubIndication.HASH_FAILURE, signatureEvidenceRecords.get(0).getSubIndication());

		XmlTimestamps timestamps = signatureEvidenceRecords.get(0).getTimestamps();
		assertNotNull(timestamps);
		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> evidenceRecordTimestamps = timestamps.getTimestamp();
		assertEquals(2, evidenceRecordTimestamps.size());
		for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp : evidenceRecordTimestamps) {
			assertEquals(Indication.PASSED, xmlTimestamp.getIndication());
		}

		DetailedReport detailedReport = reports.getDetailedReport();

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(signatureTimestamps.get(0).getId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataTimestampValidationIndication(signatureTimestamps.get(0).getId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getArchiveDataTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

		int processedTimestampsCounter = 0;
		int skippedTimestampsCounter = 0;
		for (XmlTimestamp xmlTimestamp : diagnosticData.getUsedTimestamps()) {
			XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
			if (tstBBB != null) {
				++processedTimestampsCounter;
			} else {
				++skippedTimestampsCounter;
			}
		}
		assertEquals(3, processedTimestampsCounter);
		assertEquals(0, skippedTimestampsCounter);

		assertEquals(Indication.FAILED, detailedReport.getEvidenceRecordValidationIndication(signatureEvidenceRecords.get(0).getId()));
		assertEquals(SubIndication.HASH_FAILURE, detailedReport.getEvidenceRecordValidationSubIndication(signatureEvidenceRecords.get(0).getId()));

		eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord evidenceRecord = detailedReport.getXmlEvidenceRecordById(signatureEvidenceRecords.get(0).getId());
		assertEquals(Indication.FAILED, evidenceRecord.getConclusion().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, evidenceRecord.getConclusion().getSubIndication());

		XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = evidenceRecord.getValidationProcessEvidenceRecord();
		assertEquals(Indication.FAILED, validationProcessEvidenceRecord.getConclusion().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, validationProcessEvidenceRecord.getConclusion().getSubIndication());

		int dataObjectFoundCheckCounter = 0;
		int dataObjectIntactCheckCounter = 0;
		int tstValidationConclusiveCheckCounter = 0;
		int cryptoConstraintsCheckCounter = 0;
		for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
			if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				++dataObjectFoundCheckCounter;
			} else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				assertEquals(MessageTag.BBB_CV_IRDOI_ANS.getId(), xmlConstraint.getError().getKey());
				++dataObjectIntactCheckCounter;
			} else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				++tstValidationConclusiveCheckCounter;
			} else if (MessageTag.ACCM.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				++cryptoConstraintsCheckCounter;
			}
		}
		assertEquals(1, dataObjectFoundCheckCounter);
		assertEquals(1, dataObjectIntactCheckCounter);
		assertEquals(0, tstValidationConclusiveCheckCounter);
		assertEquals(0, cryptoConstraintsCheckCounter);

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());

		XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
		assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessArchivalData.getConclusion().getSubIndication());

		boolean evidenceRecordCheckFound = false;
		boolean ltLevelAcceptableCheckFound = false;
		boolean tstValidationCheckFound = false;
		boolean pastSignatureValidationCheckFound = false;
		for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
			if (MessageTag.ADEST_IRERVPC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
				assertEquals(MessageTag.ADEST_IRERVPC_ANS.getId(), xmlConstraint.getWarning().getKey());
				evidenceRecordCheckFound = true;
			} else if (MessageTag.ARCH_LTVV.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				ltLevelAcceptableCheckFound = true;
			} else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
				tstValidationCheckFound = true;
			} else if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				assertEquals(MessageTag.PSV_IPSVC_ANS.getId(), xmlConstraint.getError().getKey());
				pastSignatureValidationCheckFound = true;
			}
		}
		assertTrue(evidenceRecordCheckFound);
		assertTrue(ltLevelAcceptableCheckFound);
		assertTrue(tstValidationCheckFound);
		assertTrue(pastSignatureValidationCheckFound);
	}

	@Test
	public void sigWithBrokenERFirstTimestampValidationTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/er-validation/sig-with-er-valid.xml"));
		assertNotNull(diagnosticData);

		XmlEvidenceRecord xmlEvidenceRecord = diagnosticData.getEvidenceRecords().get(0);
		XmlTimestamp xmlERTimestamp = xmlEvidenceRecord.getEvidenceRecordTimestamps().get(0).getTimestamp();
		xmlERTimestamp.getDigestMatchers().get(0).setDataIntact(false);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		assertEquals(1, signatureTimestamps.size());
		assertEquals(Indication.INDETERMINATE, signatureTimestamps.get(0).getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, signatureTimestamps.get(0).getSubIndication());

		List<eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(simpleReport.getFirstSignatureId());
		assertEquals(1, signatureEvidenceRecords.size());
		assertEquals(Indication.FAILED, signatureEvidenceRecords.get(0).getIndication());
		assertEquals(SubIndication.HASH_FAILURE, signatureEvidenceRecords.get(0).getSubIndication());

		XmlTimestamps timestamps = signatureEvidenceRecords.get(0).getTimestamps();
		assertNotNull(timestamps);
		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> evidenceRecordTimestamps = timestamps.getTimestamp();
		assertEquals(2, evidenceRecordTimestamps.size());

		assertEquals(Indication.FAILED, evidenceRecordTimestamps.get(0).getIndication());
		assertEquals(SubIndication.HASH_FAILURE, evidenceRecordTimestamps.get(0).getSubIndication());

		assertEquals(Indication.PASSED, evidenceRecordTimestamps.get(1).getIndication());

		DetailedReport detailedReport = reports.getDetailedReport();

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(signatureTimestamps.get(0).getId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataTimestampValidationIndication(signatureTimestamps.get(0).getId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getArchiveDataTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

		int processedTimestampsCounter = 0;
		int skippedTimestampsCounter = 0;
		for (XmlTimestamp xmlTimestamp : diagnosticData.getUsedTimestamps()) {
			XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
			if (tstBBB != null) {
				++processedTimestampsCounter;
			} else {
				++skippedTimestampsCounter;
			}
		}
		assertEquals(3, processedTimestampsCounter);
		assertEquals(0, skippedTimestampsCounter);

		assertEquals(Indication.FAILED, detailedReport.getEvidenceRecordValidationIndication(signatureEvidenceRecords.get(0).getId()));
		assertEquals(SubIndication.HASH_FAILURE, detailedReport.getEvidenceRecordValidationSubIndication(signatureEvidenceRecords.get(0).getId()));

		eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord evidenceRecord = detailedReport.getXmlEvidenceRecordById(signatureEvidenceRecords.get(0).getId());
		assertEquals(Indication.FAILED, evidenceRecord.getConclusion().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, evidenceRecord.getConclusion().getSubIndication());

		XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = evidenceRecord.getValidationProcessEvidenceRecord();
		assertEquals(Indication.FAILED, validationProcessEvidenceRecord.getConclusion().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, validationProcessEvidenceRecord.getConclusion().getSubIndication());

		int dataObjectFoundCheckCounter = 0;
		int dataObjectIntactCheckCounter = 0;
		int tstValidationConclusiveCheckCounter = 0;
		int cryptoConstraintsCheckCounter = 0;
		for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
			if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				++dataObjectFoundCheckCounter;
			} else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				++dataObjectIntactCheckCounter;
			} else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getError().getKey());
				++tstValidationConclusiveCheckCounter;
			} else if (MessageTag.ACCM.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				++cryptoConstraintsCheckCounter;
			}
		}
		assertEquals(1, dataObjectFoundCheckCounter);
		assertEquals(1, dataObjectIntactCheckCounter);
		assertEquals(1, tstValidationConclusiveCheckCounter);
		assertEquals(0, cryptoConstraintsCheckCounter);

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());

		XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
		assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessArchivalData.getConclusion().getSubIndication());

		boolean evidenceRecordCheckFound = false;
		boolean ltLevelAcceptableCheckFound = false;
		boolean tstValidationCheckFound = false;
		boolean pastSignatureValidationCheckFound = false;
		for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
			if (MessageTag.ADEST_IRERVPC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
				assertEquals(MessageTag.ADEST_IRERVPC_ANS.getId(), xmlConstraint.getWarning().getKey());
				evidenceRecordCheckFound = true;
			} else if (MessageTag.ARCH_LTVV.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				ltLevelAcceptableCheckFound = true;
			} else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
				tstValidationCheckFound = true;
			} else if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				assertEquals(MessageTag.PSV_IPSVC_ANS.getId(), xmlConstraint.getError().getKey());
				pastSignatureValidationCheckFound = true;
			}
		}
		assertTrue(evidenceRecordCheckFound);
		assertTrue(ltLevelAcceptableCheckFound);
		assertTrue(tstValidationCheckFound);
		assertTrue(pastSignatureValidationCheckFound);
	}

	@Test
	public void sigWithBrokenERSecondTimestampValidationTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/er-validation/sig-with-er-valid.xml"));
		assertNotNull(diagnosticData);

		XmlEvidenceRecord xmlEvidenceRecord = diagnosticData.getEvidenceRecords().get(0);
		XmlTimestamp xmlERTimestamp = xmlEvidenceRecord.getEvidenceRecordTimestamps().get(1).getTimestamp();
		xmlERTimestamp.getDigestMatchers().get(0).setDataIntact(false);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		assertEquals(1, signatureTimestamps.size());
		assertEquals(Indication.INDETERMINATE, signatureTimestamps.get(0).getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, signatureTimestamps.get(0).getSubIndication());

		List<eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(simpleReport.getFirstSignatureId());
		assertEquals(1, signatureEvidenceRecords.size());
		assertEquals(Indication.FAILED, signatureEvidenceRecords.get(0).getIndication());
		assertEquals(SubIndication.HASH_FAILURE, signatureEvidenceRecords.get(0).getSubIndication());

		XmlTimestamps timestamps = signatureEvidenceRecords.get(0).getTimestamps();
		assertNotNull(timestamps);
		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> evidenceRecordTimestamps = timestamps.getTimestamp();
		assertEquals(2, evidenceRecordTimestamps.size());

		assertEquals(Indication.PASSED, evidenceRecordTimestamps.get(0).getIndication());

		assertEquals(Indication.FAILED, evidenceRecordTimestamps.get(1).getIndication());
		assertEquals(SubIndication.HASH_FAILURE, evidenceRecordTimestamps.get(1).getSubIndication());

		DetailedReport detailedReport = reports.getDetailedReport();

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(signatureTimestamps.get(0).getId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataTimestampValidationIndication(signatureTimestamps.get(0).getId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getArchiveDataTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

		int processedTimestampsCounter = 0;
		int skippedTimestampsCounter = 0;
		for (XmlTimestamp xmlTimestamp : diagnosticData.getUsedTimestamps()) {
			XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
			if (tstBBB != null) {
				++processedTimestampsCounter;
			} else {
				++skippedTimestampsCounter;
			}
		}
		assertEquals(3, processedTimestampsCounter);
		assertEquals(0, skippedTimestampsCounter);

		assertEquals(Indication.FAILED, detailedReport.getEvidenceRecordValidationIndication(signatureEvidenceRecords.get(0).getId()));
		assertEquals(SubIndication.HASH_FAILURE, detailedReport.getEvidenceRecordValidationSubIndication(signatureEvidenceRecords.get(0).getId()));

		eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord evidenceRecord = detailedReport.getXmlEvidenceRecordById(signatureEvidenceRecords.get(0).getId());
		assertEquals(Indication.FAILED, evidenceRecord.getConclusion().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, evidenceRecord.getConclusion().getSubIndication());

		XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = evidenceRecord.getValidationProcessEvidenceRecord();
		assertEquals(Indication.FAILED, validationProcessEvidenceRecord.getConclusion().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, validationProcessEvidenceRecord.getConclusion().getSubIndication());

		int dataObjectFoundCheckCounter = 0;
		int dataObjectIntactCheckCounter = 0;
		int tstValidationValidCheckCounter = 0;
		int tstValidationInvalidCheckCounter = 0;
		int cryptoConstraintsCheckCounter = 0;
		for (XmlConstraint xmlConstraint : validationProcessEvidenceRecord.getConstraint()) {
			if (MessageTag.BBB_CV_IRDOF.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				++dataObjectFoundCheckCounter;
			} else if (MessageTag.BBB_CV_IRDOI.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				++dataObjectIntactCheckCounter;
			} else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
				if (XmlStatus.OK.equals(xmlConstraint.getStatus())) {
					++tstValidationValidCheckCounter;
				} else if (XmlStatus.NOT_OK.equals(xmlConstraint.getStatus())) {
					assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getError().getKey());
					++tstValidationInvalidCheckCounter;
				}
			} else if (MessageTag.ACCM.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				++cryptoConstraintsCheckCounter;
			}
		}
		assertEquals(1, dataObjectFoundCheckCounter);
		assertEquals(1, dataObjectIntactCheckCounter);
		assertEquals(1, tstValidationValidCheckCounter);
		assertEquals(1, tstValidationInvalidCheckCounter);
		assertEquals(0, cryptoConstraintsCheckCounter);

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());

		XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
		assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessArchivalData.getConclusion().getSubIndication());

		boolean evidenceRecordCheckFound = false;
		boolean ltLevelAcceptableCheckFound = false;
		boolean tstValidationCheckFound = false;
		boolean pastSignatureValidationCheckFound = false;
		for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
			if (MessageTag.ADEST_IRERVPC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
				assertEquals(MessageTag.ADEST_IRERVPC_ANS.getId(), xmlConstraint.getWarning().getKey());
				evidenceRecordCheckFound = true;
			} else if (MessageTag.ARCH_LTVV.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				ltLevelAcceptableCheckFound = true;
			} else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
				tstValidationCheckFound = true;
			} else if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				assertEquals(MessageTag.PSV_IPSVC_ANS.getId(), xmlConstraint.getError().getKey());
				pastSignatureValidationCheckFound = true;
			}
		}
		assertTrue(evidenceRecordCheckFound);
		assertTrue(ltLevelAcceptableCheckFound);
		assertTrue(tstValidationCheckFound);
		assertTrue(pastSignatureValidationCheckFound);
	}

	@Test
	public void sigWithERLTValidationTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/er-validation/sig-with-er-valid.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationLevel(ValidationLevel.LONG_TERM_DATA);

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
		assertEquals(1, signatureTimestamps.size());
		assertEquals(Indication.INDETERMINATE, signatureTimestamps.get(0).getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, signatureTimestamps.get(0).getSubIndication());

		List<eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(simpleReport.getFirstSignatureId());
		assertEquals(0, signatureEvidenceRecords.size());

		DetailedReport detailedReport = reports.getDetailedReport();

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(signatureTimestamps.get(0).getId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

		int processedTimestampsCounter = 0;
		int skippedTimestampsCounter = 0;
		for (XmlTimestamp xmlTimestamp : diagnosticData.getUsedTimestamps()) {
			XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
			if (tstBBB != null) {
				assertFalse(xmlTimestamp.getType().isEvidenceRecordTimestamp());
				++processedTimestampsCounter;
			} else {
				assertTrue(xmlTimestamp.getType().isEvidenceRecordTimestamp());
				++skippedTimestampsCounter;
			}
		}
		assertEquals(1, processedTimestampsCounter);
		assertEquals(2, skippedTimestampsCounter);

		assertNull(detailedReport.getArchiveDataTimestampValidationIndication(signatureTimestamps.get(0).getId()));
		assertNull(detailedReport.getArchiveDataTimestampValidationSubIndication(signatureTimestamps.get(0).getId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertNull(detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
		assertNull(detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());

		XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
		assertNull(validationProcessArchivalData);
	}

	@Test
	public void valAssuredSTRevocationSkipTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_st_val_assured.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints signingCertificate = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();

		CertificateValuesConstraint constraint = new CertificateValuesConstraint();
		constraint.setLevel(Level.IGNORE);
		MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
		certExtensionsConstraint.getId().add("0.4.0.194121.2.1");
		constraint.setCertificateExtensions(certExtensionsConstraint);
		signingCertificate.setRevocationDataSkip(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.TOTAL_PASSED, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, xcv.getConclusion().getSubIndication());

		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(4, subXCVs.size());

		XmlSubXCV xmlSubXCV = subXCVs.get(0);
		assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, xmlSubXCV.getConclusion().getSubIndication());

		boolean revocationSkipCheckFound = false;
		boolean revocationDataPresentCheckFound = false;
		for (XmlConstraint xmlConstraint : xmlSubXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
				revocationSkipCheckFound = true;
			} else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
				revocationDataPresentCheckFound = true;
			}
		}
		assertTrue(revocationSkipCheckFound);
		assertFalse(revocationDataPresentCheckFound);
		
		for (XmlSubXCV subXCV : subXCVs) {
			if (xmlSubXCV != subXCV) {
				assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

				revocationSkipCheckFound = false;
				revocationDataPresentCheckFound = false;
				for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
					if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
						assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
						revocationSkipCheckFound = true;
					} else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
						revocationDataPresentCheckFound = true;
					}
				}
				assertFalse(revocationSkipCheckFound);
				assertTrue(revocationDataPresentCheckFound || subXCV.isTrustAnchor());
			}
		}

		XmlPSV psv = signatureBBB.getPSV();
		assertNotNull(psv);
		assertEquals(Indication.PASSED, psv.getConclusion().getIndication());

		boolean revocationSelectorResultCheckFound = false;
		for (XmlConstraint xmlConstraint : psv.getConstraint()) {
			if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
				revocationSelectorResultCheckFound = true;
				break;
			}
		}
		assertFalse(revocationSelectorResultCheckFound);

		XmlVTS vts = signatureBBB.getVTS();
		assertNotNull(vts);
		assertEquals(Indication.PASSED, vts.getConclusion().getIndication());

		int revocationCheckValidCounter = 0;
		int revocationCheckSkippedCounter = 0;
		for (XmlConstraint xmlConstraint : vts.getConstraint()) {
			if (MessageTag.BBB_VTS_IRDPFC.getId().equals(xmlConstraint.getName().getKey()) &&
					XmlStatus.OK.equals(xmlConstraint.getStatus())) {
					++revocationCheckValidCounter;
			} else if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey()) &&
					XmlStatus.IGNORED.equals(xmlConstraint.getStatus())) {
				++revocationCheckSkippedCounter;
			}
		}
		assertEquals(2, revocationCheckValidCounter);
		assertEquals(1, revocationCheckSkippedCounter);

		checkReports(reports);
	}

	@Test
	public void certPolicyInformRevocationSkipTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_st_val_assured.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints signingCertificate = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();

		CertificateValuesConstraint constraint = new CertificateValuesConstraint();
		constraint.setLevel(Level.INFORM);
		MultiValuesConstraint certPolicyConstraint = new MultiValuesConstraint();
		certPolicyConstraint.getId().add("1.3.6.2.14");
		constraint.setCertificatePolicies(certPolicyConstraint);
		signingCertificate.setRevocationDataSkip(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.TOTAL_PASSED, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(detailedReport.getAdESValidationInfos(detailedReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());
		assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getInfos()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, xcv.getConclusion().getSubIndication());
		assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getInfos()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(4, subXCVs.size());

		XmlSubXCV xmlSubXCV = subXCVs.get(0);
		assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, xmlSubXCV.getConclusion().getSubIndication());
		assertTrue(checkMessageValuePresence(convert(xmlSubXCV.getConclusion().getInfos()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

		boolean revocationSkipCheckFound = false;
		boolean revocationDataPresentCheckFound = false;
		for (XmlConstraint xmlConstraint : xmlSubXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.INFORMATION, xmlConstraint.getStatus());
				revocationSkipCheckFound = true;
			} else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
				revocationDataPresentCheckFound = true;
			}
		}
		assertTrue(revocationSkipCheckFound);
		assertFalse(revocationDataPresentCheckFound);

		for (XmlSubXCV subXCV : subXCVs) {
			if (xmlSubXCV != subXCV) {
				assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());
				assertFalse(checkMessageValuePresence(convert(subXCV.getConclusion().getInfos()),
						i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

				revocationSkipCheckFound = false;
				revocationDataPresentCheckFound = false;
				for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
					if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
						assertEquals(XmlStatus.INFORMATION, xmlConstraint.getStatus());
						revocationSkipCheckFound = true;
					} else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
						revocationDataPresentCheckFound = true;
					}
				}
				assertFalse(revocationSkipCheckFound);
				assertTrue(revocationDataPresentCheckFound || subXCV.isTrustAnchor());
			}
		}

		XmlPSV psv = signatureBBB.getPSV();
		assertNotNull(psv);
		assertEquals(Indication.PASSED, psv.getConclusion().getIndication());

		boolean revocationSelectorResultCheckFound = false;
		for (XmlConstraint xmlConstraint : psv.getConstraint()) {
			if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
				revocationSelectorResultCheckFound = true;
				break;
			}
		}
		assertFalse(revocationSelectorResultCheckFound);

		XmlVTS vts = signatureBBB.getVTS();
		assertNotNull(vts);
		assertEquals(Indication.PASSED, vts.getConclusion().getIndication());

		int revocationCheckValidCounter = 0;
		int revocationCheckSkippedCounter = 0;
		for (XmlConstraint xmlConstraint : vts.getConstraint()) {
			if (MessageTag.BBB_VTS_IRDPFC.getId().equals(xmlConstraint.getName().getKey()) &&
					XmlStatus.OK.equals(xmlConstraint.getStatus())) {
				++revocationCheckValidCounter;
			} else if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey()) &&
					XmlStatus.INFORMATION.equals(xmlConstraint.getStatus())) {
				++revocationCheckSkippedCounter;
			}
		}
		assertEquals(2, revocationCheckValidCounter);
		assertEquals(1, revocationCheckSkippedCounter);

		checkReports(reports);
	}

	@Test
	public void revocationSkipFailureTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_st_val_assured.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints signingCertificate = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();

		CertificateValuesConstraint constraint = new CertificateValuesConstraint();
		constraint.setLevel(Level.IGNORE);
		MultiValuesConstraint certPolicyConstraint = new MultiValuesConstraint();
		certPolicyConstraint.getId().add("1.2.3.4.5"); // wrong policy OID
		constraint.setCertificatePolicies(certPolicyConstraint);
		signingCertificate.setRevocationDataSkip(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getFinalSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, signatureBBB.getConclusion().getSubIndication());

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(4, subXCVs.size());

		XmlSubXCV xmlSubXCV = subXCVs.get(0);
		assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlSubXCV.getConclusion().getSubIndication());

		boolean revocationSkipCheckFound = false;
		boolean revocationDataPresentCheckFound = false;
		boolean revocationDataAcceptableCheckFound = false;
		for (XmlConstraint xmlConstraint : xmlSubXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
				revocationSkipCheckFound = true;
			} else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				revocationDataPresentCheckFound = true;
			} else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				revocationDataAcceptableCheckFound = true;
			}
		}
		assertFalse(revocationSkipCheckFound);
		assertTrue(revocationDataPresentCheckFound);
		assertTrue(revocationDataAcceptableCheckFound);

		for (XmlSubXCV subXCV : subXCVs) {
			if (xmlSubXCV != subXCV) {
				assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

				revocationDataPresentCheckFound = false;
				revocationDataAcceptableCheckFound = false;
				for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
					if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
						revocationSkipCheckFound = true;
					} else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
						assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
						revocationDataPresentCheckFound = true;
					} else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
						assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
						revocationDataAcceptableCheckFound = true;
					}
				}
				assertFalse(revocationSkipCheckFound);
				assertTrue(revocationDataPresentCheckFound || subXCV.isTrustAnchor());
				assertTrue(revocationDataAcceptableCheckFound || subXCV.isTrustAnchor());
			}
		}

		XmlPSV psv = signatureBBB.getPSV();
		assertNull(psv);

		XmlVTS vts = signatureBBB.getVTS();
		assertNull(vts);

		checkReports(reports);
	}

	@Test
	public void revocationSkipCertPolicyWrongPlaceTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_st_val_assured.xml"));
		assertNotNull(diagnosticData);

		ValidationPolicy validationPolicy = loadDefaultPolicy();
		CertificateConstraints signingCertificate = validationPolicy.getSignatureConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();
		signingCertificate.setRevocationDataSkip(new CertificateValuesConstraint());

		CertificateConstraints revocationConstraints = validationPolicy.getRevocationConstraints()
				.getBasicSignatureConstraints().getSigningCertificate();

		CertificateValuesConstraint constraint = new CertificateValuesConstraint();
		constraint.setLevel(Level.INFORM);
		MultiValuesConstraint certPolicyConstraint = new MultiValuesConstraint();
		certPolicyConstraint.getId().add("1.3.6.2.14");
		constraint.setCertificatePolicies(certPolicyConstraint);
		revocationConstraints.setRevocationDataSkip(constraint);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(validationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getFinalSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, signatureBBB.getConclusion().getSubIndication());

		XmlXCV xcv = signatureBBB.getXCV();
		assertNotNull(xcv);
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

		List<XmlSubXCV> subXCVs = xcv.getSubXCV();
		assertEquals(4, subXCVs.size());

		XmlSubXCV xmlSubXCV = subXCVs.get(0);
		assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
		assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlSubXCV.getConclusion().getSubIndication());

		boolean revocationSkipCheckFound = false;
		boolean revocationDataPresentCheckFound = false;
		boolean revocationDataAcceptableCheckFound = false;
		for (XmlConstraint xmlConstraint : xmlSubXCV.getConstraint()) {
			if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
				revocationSkipCheckFound = true;
			} else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
				revocationDataPresentCheckFound = true;
			} else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				revocationDataAcceptableCheckFound = true;
			}
		}
		assertFalse(revocationSkipCheckFound);
		assertTrue(revocationDataPresentCheckFound);
		assertTrue(revocationDataAcceptableCheckFound);

		for (XmlSubXCV subXCV : subXCVs) {
			if (xmlSubXCV != subXCV) {
				assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

				revocationDataPresentCheckFound = false;
				revocationDataAcceptableCheckFound = false;
				for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
					if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
						revocationSkipCheckFound = true;
					} else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
						assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
						revocationDataPresentCheckFound = true;
					} else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
						assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
						revocationDataAcceptableCheckFound = true;
					}
				}
				assertFalse(revocationSkipCheckFound);
				assertTrue(revocationDataPresentCheckFound || subXCV.isTrustAnchor());
				assertTrue(revocationDataAcceptableCheckFound || subXCV.isTrustAnchor());
			}
		}

		XmlPSV psv = signatureBBB.getPSV();
		assertNull(psv);

		XmlVTS vts = signatureBBB.getVTS();
		assertNull(vts);

		checkReports(reports);
	}

	@Test
	public void digestAlgorithmCheckMergeTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_many_references.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotNull(detailedReport);
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlSAV sav = signatureBBB.getSAV();
		assertNotNull(sav);

		int digestAlgorithmCheckCounter = 0;
		boolean manifestCheckFound = false;
		boolean signedPropertiesCheckFound = false;
		boolean manifestEntriesCheckFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_MAN))) {
					assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAME,
							DigestAlgorithm.SHA256.getName(), ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()), MessageTag.ACCM_POS_MAN, "")));
					manifestCheckFound = true;
				} else if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_SIGND_PRT))) {
					assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAME,
							DigestAlgorithm.SHA256.getName(), ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()), MessageTag.ACCM_POS_SIGND_PRT, "")));
					signedPropertiesCheckFound = true;
				} else if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_MAN_ENT_PL))) {
					assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAMES,
							DigestAlgorithm.SHA512.getName(), ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()), MessageTag.ACCM_POS_MAN_ENT_PL, "")));
					manifestEntriesCheckFound = true;
				}
				++digestAlgorithmCheckCounter;
			}
		}
		assertEquals(5, digestAlgorithmCheckCounter); // + sig creation + signed-certificate ref check
		assertTrue(manifestCheckFound);
		assertTrue(signedPropertiesCheckFound);
		assertTrue(manifestEntriesCheckFound);
	}

	@Test
	public void digestAlgorithmCheckMergeFailTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag_data_many_references.xml"));
		assertNotNull(diagnosticData);

		diagnosticData.getSignatures().get(0).getDigestMatchers().get(2).setDigestMethod(DigestAlgorithm.SHA1);

		Date tstProductionDate = diagnosticData.getUsedTimestamps().get(0).getProductionTime();

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotNull(detailedReport);
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);

		XmlSAV sav = signatureBBB.getSAV();
		assertNotNull(sav);

		int digestAlgorithmCheckCounter = 0;
		boolean manifestCheckFound = false;
		boolean signedPropertiesCheckFound = false;
		boolean manifestEntriesCheckSuccessFound = false;
		boolean manifestEntriesCheckFailureFound = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
				if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_MAN))) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAME,
							DigestAlgorithm.SHA256.getName(), ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()), MessageTag.ACCM_POS_MAN, "")));
					manifestCheckFound = true;
				} else if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_SIGND_PRT))) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAME,
							DigestAlgorithm.SHA256.getName(), ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()), MessageTag.ACCM_POS_SIGND_PRT, "")));
					signedPropertiesCheckFound = true;
				} else if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_MAN_ENT_PL))) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAMES,
							DigestAlgorithm.SHA512.getName(), ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()), MessageTag.ACCM_POS_MAN_ENT_PL, "")));
					manifestEntriesCheckSuccessFound = true;
				} else if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_MAN_ENT))) {
					assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
					assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE_WITH_REF_WITH_NAME,
							i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1.getName(), MessageTag.ACCM_POS_MAN_ENT),
							ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate()), "")));
					manifestEntriesCheckFailureFound = true;
				}
				++digestAlgorithmCheckCounter;
			}
		}
		assertEquals(5, digestAlgorithmCheckCounter); // + sig creation (sign-cert not executed because of sha1 failure)
		assertTrue(manifestCheckFound);
		assertTrue(signedPropertiesCheckFound); // fails before
		assertTrue(manifestEntriesCheckSuccessFound);
		assertTrue(manifestEntriesCheckFailureFound);

		digestAlgorithmCheckCounter = 0;
		manifestCheckFound = false;
		signedPropertiesCheckFound = false;
		manifestEntriesCheckSuccessFound = false;
		manifestEntriesCheckFailureFound = false;

		XmlPSV psv = signatureBBB.getPSV();
		assertNotNull(psv);
		for (XmlConstraint constraint : psv.getConstraint()) {
			if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
				if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_MAN))) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAME,
							DigestAlgorithm.SHA256.getName(), ValidationProcessUtils.getFormattedDate(tstProductionDate), MessageTag.ACCM_POS_MAN, "")));
					manifestCheckFound = true;
				} else if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_SIGND_PRT))) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAME,
							DigestAlgorithm.SHA256.getName(), ValidationProcessUtils.getFormattedDate(tstProductionDate), MessageTag.ACCM_POS_SIGND_PRT, "")));
					signedPropertiesCheckFound = true;
				} else if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_MAN_ENT_PL))) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAMES,
							DigestAlgorithm.SHA512.getName(), ValidationProcessUtils.getFormattedDate(tstProductionDate), MessageTag.ACCM_POS_MAN_ENT_PL, "")));
					manifestEntriesCheckSuccessFound = true;
				} else if (constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.ACCM_POS_MAN_ENT))) {
					assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
					assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE_WITH_REF_WITH_NAME,
							i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1.getName(), MessageTag.ACCM_POS_MAN_ENT),
							ValidationProcessUtils.getFormattedDate(tstProductionDate), "")));
					manifestEntriesCheckFailureFound = true;
				}
				++digestAlgorithmCheckCounter;
			}
		}
		assertEquals(5, digestAlgorithmCheckCounter); // + sig creation (sign-cert not executed because of sha1 failure)
		assertTrue(manifestCheckFound);
		assertTrue(signedPropertiesCheckFound); // fails before
		assertTrue(manifestEntriesCheckSuccessFound);
		assertTrue(manifestEntriesCheckFailureFound);
	}

	@Test
	public void erDigestAlgorithmCheckMergeTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/er-validation/diag_data_er_many_references.xml"));
		assertNotNull(diagnosticData);

		Date tstProductionDate = diagnosticData.getUsedTimestamps().get(0).getProductionTime();

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotNull(detailedReport);
		eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord xmlEvidenceRecord =
				detailedReport.getXmlEvidenceRecordById(detailedReport.getFirstEvidenceRecordId());
		assertNotNull(xmlEvidenceRecord);
		XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
		assertNotNull(validationProcessEvidenceRecord);

		int digestAlgorithmCheckCounter = 0;
		for (XmlConstraint constraint : validationProcessEvidenceRecord.getConstraint()) {
			if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				assertTrue(constraint.getAdditionalInfo().contains(i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAMES,
						DigestAlgorithm.SHA512.getName(), ValidationProcessUtils.getFormattedDate(tstProductionDate), MessageTag.ACCM_POS_ER_ADO_PL, "")));
				++digestAlgorithmCheckCounter;
			}
		}
		assertEquals(1, digestAlgorithmCheckCounter);
	}

	@Test
	public void erDiffDigestAlgorithmsCheckMergeTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/er-validation/diag_data_er_many_references.xml"));
		assertNotNull(diagnosticData);

		XmlEvidenceRecord evidenceRecord = diagnosticData.getEvidenceRecords().get(0);
		evidenceRecord.getDigestMatchers().get(0).setDigestMethod(DigestAlgorithm.SHA256);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotNull(detailedReport);
		eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord xmlEvidenceRecord =
				detailedReport.getXmlEvidenceRecordById(detailedReport.getFirstEvidenceRecordId());
		assertNotNull(xmlEvidenceRecord);
		XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
		assertNotNull(validationProcessEvidenceRecord);

		int digestAlgorithmCheckCounter = 0;
		boolean sha256AlgoCheckFound = false;
		boolean sha512AlgoCheckFound = false;
		for (XmlConstraint constraint : validationProcessEvidenceRecord.getConstraint()) {
			if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				if (constraint.getAdditionalInfo().contains(DigestAlgorithm.SHA256.getName())) {
					sha256AlgoCheckFound = true;
				} else if (constraint.getAdditionalInfo().contains(DigestAlgorithm.SHA512.getName())) {
					sha512AlgoCheckFound = true;
				}
				++digestAlgorithmCheckCounter;
			}
		}
		assertEquals(2, digestAlgorithmCheckCounter);
		assertTrue(sha256AlgoCheckFound);
		assertTrue(sha512AlgoCheckFound);
	}

	@Test
	public void erDiffDigestAlgorithmsCheckMergeFailTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/er-validation/diag_data_er_many_references.xml"));
		assertNotNull(diagnosticData);

		XmlEvidenceRecord evidenceRecord = diagnosticData.getEvidenceRecords().get(0);
		evidenceRecord.getDigestMatchers().get(0).setDigestMethod(DigestAlgorithm.SHA256);
		evidenceRecord.getDigestMatchers().get(evidenceRecord.getDigestMatchers().size() - 1).setDigestMethod(DigestAlgorithm.SHA1);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotNull(detailedReport);
		eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord xmlEvidenceRecord =
				detailedReport.getXmlEvidenceRecordById(detailedReport.getFirstEvidenceRecordId());
		assertNotNull(xmlEvidenceRecord);
		XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
		assertNotNull(validationProcessEvidenceRecord);

		int digestAlgorithmCheckCounter = 0;
		boolean sha1AlgoCheckFound = false;
		boolean sha256AlgoCheckFound = false;
		boolean sha512AlgoCheckFound = false;
		for (XmlConstraint constraint : validationProcessEvidenceRecord.getConstraint()) {
			if (MessageTag.ACCM.getId().equals(constraint.getName().getKey())) {
				if (constraint.getAdditionalInfo().contains(DigestAlgorithm.SHA256.getName())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					sha256AlgoCheckFound = true;
				} else if (constraint.getAdditionalInfo().contains(DigestAlgorithm.SHA512.getName())) {
					assertEquals(XmlStatus.OK, constraint.getStatus());
					sha512AlgoCheckFound = true;
				} else if (constraint.getAdditionalInfo().contains(DigestAlgorithm.SHA1.getName())) {
					assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
					assertEquals(MessageTag.ASCCM_AR_ANS_ANR.getId(), constraint.getError().getKey());
					assertEquals(i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_ER_ADO),
							constraint.getError().getValue());
					sha1AlgoCheckFound = true;
				}
				++digestAlgorithmCheckCounter;
			}
		}
		assertEquals(3, digestAlgorithmCheckCounter);
		assertTrue(sha1AlgoCheckFound);
		assertTrue(sha256AlgoCheckFound);
		assertTrue(sha512AlgoCheckFound);
	}

	@Test
	public void diagDataNotNull() throws Exception {
		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(null);
		executor.setValidationPolicy(loadPolicyNoRevoc());
		executor.setCurrentTime(new Date());

		Exception exception = assertThrows(NullPointerException.class, () -> executor.execute());
		assertEquals("The diagnostic data is missing", exception.getMessage());
	}

	@Test
	public void validationPolicyNotNull() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/DSS-1330-diag-data.xml"));

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(null);
		executor.setCurrentTime(new Date());

		Exception exception = assertThrows(NullPointerException.class, () -> executor.execute());
		assertEquals("The validation policy is missing", exception.getMessage());
	}

	@Test
	public void currentDateNotNull() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/DSS-1330-diag-data.xml"));

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicyNoRevoc());
		executor.setCurrentTime(null);
		Exception exception = assertThrows(NullPointerException.class, () -> executor.execute());
		assertEquals("The current time is missing", exception.getMessage());
	}

	@Test
	public void validationLevelNotNull() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/DSS-1330-diag-data.xml"));

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicyNoRevoc());
		executor.setCurrentTime(new Date());
		executor.setValidationLevel(null);

		Exception exception = assertThrows(NullPointerException.class, () -> executor.execute());
		assertEquals("The validation level is missing", exception.getMessage());
	}
	
	@Test
	public void getCertQualificationTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/DSS-1330-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		DetailedReport detailedReport = reports.getDetailedReport();

		assertEquals(CertificateQualification.NA, detailedReport.getCertificateQualificationAtIssuance("certId"));
		assertEquals(CertificateQualification.NA, detailedReport.getCertificateQualificationAtValidation("certId"));
		Exception exception = assertThrows(UnsupportedOperationException.class, () -> detailedReport.getCertificateXCVConclusion("certId"));
		assertEquals("Only supported in report for certificate", exception.getMessage());
	}

	@Test
	public void qcWithConflictInTypesTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/sig-qualification/post-eidas-qc-types-conflict.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.UNKNOWN_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void noQCWithConflictInTypesTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/sig-qualification/post-eidas-no-qc-types-conflict.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.UNKNOWN, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void noQcComplianceForESigTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/sig-qualification/post-eidas-no-qc-compliance-for-esig.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		// for eSig only when type or QcStatement is defined
		assertEquals(SignatureQualification.UNKNOWN_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void qcComplianceForESigTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/sig-qualification/post-eidas-no-qc-compliance-for-esig.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate signingCertificate = xmlSignature.getSigningCertificate().getCertificate();

		XmlQcStatements qcStatements = null;
		for (XmlCertificateExtension certificateExtension : signingCertificate.getCertificateExtensions()) {
			if (CertificateExtensionEnum.QC_STATEMENTS.getOid().equals(certificateExtension.getOID())) {
				qcStatements = (XmlQcStatements) certificateExtension;
			}
		}
		if (qcStatements == null) {
			qcStatements = new XmlQcStatements();
			qcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
			signingCertificate.getCertificateExtensions().add(qcStatements);

		}

		XmlQcCompliance qcCompliance = new XmlQcCompliance();
		qcCompliance.setPresent(true);
		qcStatements.setQcCompliance(qcCompliance);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		// QcStatement is default for eSig
		assertEquals(SignatureQualification.ADESIG_QC, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void noQcComplianceForESigWithQSCDTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/sig-qualification/post-eidas-no-qc-compliance-for-esig-sscd.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		// for eSig only when type or QcStatement is defined
		assertEquals(SignatureQualification.UNKNOWN_QC_QSCD, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void qcComplianceForESigWithQSCDTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/sig-qualification/post-eidas-no-qc-compliance-for-esig-sscd.xml"));
		assertNotNull(diagnosticData);

		XmlSignature xmlSignature = diagnosticData.getSignatures().get(0);
		XmlCertificate signingCertificate = xmlSignature.getSigningCertificate().getCertificate();

		XmlQcStatements qcStatements = null;
		for (XmlCertificateExtension certificateExtension : signingCertificate.getCertificateExtensions()) {
			if (CertificateExtensionEnum.QC_STATEMENTS.getOid().equals(certificateExtension.getOID())) {
				qcStatements = (XmlQcStatements) certificateExtension;
			}
		}
		if (qcStatements == null) {
			qcStatements = new XmlQcStatements();
			qcStatements.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
			signingCertificate.getCertificateExtensions().add(qcStatements);

		}

		XmlQcCompliance qcCompliance = new XmlQcCompliance();
		qcCompliance.setPresent(true);
		qcStatements.setQcCompliance(qcCompliance);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		// for eSig only when type or QcStatement is defined
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		List<XmlTrustServiceProvider> trustServices = signingCertificate.getTrustServiceProviders();
		String tlId = trustServices.get(0).getTL().getId();

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlTLAnalysis tlAnalysis = detailedReport.getTLAnalysisById(tlId);
		assertNotNull(tlAnalysis);

		// Ensure no MRA is enacted
		boolean mraFound = false;
		for (XmlConstraint constraint : tlAnalysis.getConstraint()) {
			if (MessageTag.QUAL_TL_IMRA.getId().equals(constraint.getName().getKey())) {
				mraFound = true;
				break;
			}
		}
		assertFalse(mraFound);

		eu.europa.esig.dss.detailedreport.jaxb.XmlSignature signature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		XmlValidationSignatureQualification validationSignatureQualification = signature.getValidationSignatureQualification();
		assertEquals(SignatureQualification.QESIG, validationSignatureQualification.getSignatureQualification());

		assertEquals(Indication.PASSED, validationSignatureQualification.getConclusion().getIndication());
		assertFalse(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getInfos()),
				i18nProvider.getMessage(MessageTag.QUAL_TL_IMRA_ANS)));
		assertFalse(checkMessageValuePresence(convert(validationSignatureQualification.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.QUAL_HAS_METS_ANS)));

		List<XmlValidationCertificateQualification> validationCertificateQualification = validationSignatureQualification.getValidationCertificateQualification();
		assertEquals(2, validationCertificateQualification.size());

		for (XmlValidationCertificateQualification certificateQualification : validationCertificateQualification) {
			boolean mraTrustServiceCheckFound = false;
			for (XmlConstraint constraint : certificateQualification.getConstraint()) {
				if (MessageTag.QUAL_HAS_METS.getId().equals(constraint.getName().getKey())) {
					mraTrustServiceCheckFound = true;
					break;
				}
			}
			assertFalse(mraTrustServiceCheckFound);
		}
	}

	@Test
	public void inconsistentTlByTypeWithQCAndQSCDTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/sig-qualification/inconsistent-tl-by-type.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureQualification.UNKNOWN_QC_QSCD, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
	}

	private void validateBestSigningTimes(Reports reports) {
		DetailedReport detailedReport = reports.getDetailedReport();
		List<eu.europa.esig.dss.detailedreport.jaxb.XmlSignature> xmlSignatures = detailedReport.getSignatures();
		for (eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature : xmlSignatures) {
			assertNotNull(xmlSignature.getValidationProcessBasicSignature().getProofOfExistence());
			assertNotNull(xmlSignature.getValidationProcessLongTermData().getProofOfExistence());
			assertNotNull(xmlSignature.getValidationProcessArchivalData().getProofOfExistence());
		}
	}

	private ValidationPolicy loadTLPolicy() throws Exception {
		return ValidationPolicyFacade.newFacade().getTrustedListValidationPolicy();
	}

	private ValidationPolicy loadPolicyNoRevoc() throws Exception {
		return ValidationPolicyFacade.newFacade().getValidationPolicy(new File("src/test/resources/policy/constraint-no-revoc.xml"));
	}

	private ValidationPolicy loadPolicyRevocSha1OK() throws Exception {
		return ValidationPolicyFacade.newFacade().getValidationPolicy(new File("src/test/resources/policy/revocation-sha1-ok-policy.xml"));
	}

	private ValidationPolicy loadPolicyCryptoWarn() throws Exception {
		EtsiValidationPolicy defaultPolicy = (EtsiValidationPolicy) ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
		CryptographicConstraint cryptographicConstraint = defaultPolicy.getDefaultCryptographicConstraint();
		cryptographicConstraint.setLevel(Level.WARN);
		cryptographicConstraint.getAlgoExpirationDate().setLevel(Level.WARN);
		return defaultPolicy;
	}

}
