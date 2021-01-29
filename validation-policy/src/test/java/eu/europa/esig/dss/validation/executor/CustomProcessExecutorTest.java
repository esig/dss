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
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicInformation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureDigestReference;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.common.Message;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.ContainerConstraints;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.Model;
import eu.europa.esig.dss.policy.jaxb.ModelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.RevocationConstraints;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.SignedAttributesConstraints;
import eu.europa.esig.dss.policy.jaxb.TimestampConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
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

import javax.xml.bind.JAXB;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

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

//		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		assertNull(simpleReport.getSignatureExtensionPeriodMin(simpleReport.getFirstSignatureId()));
		assertNull(simpleReport.getSignatureExtensionPeriodMax(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

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
		assertEquals(SubIndication.NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

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
		
		XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getSignatures().get(0).getValidationProcessArchivalData();
		List<XmlConstraint> constraints = validationProcessArchivalData.getConstraint();
		
		List<String> timestampIds = detailedReport.getTimestampIds();
		
		int basicValidationTSTFailedCounter = 0;
		for (String timestampId : timestampIds) {
			Indication timestampValidationIndication = detailedReport.getTimestampValidationIndication(timestampId);
			if (!Indication.PASSED.equals(timestampValidationIndication)) {
				assertNotNull(detailedReport.getTimestampValidationSubIndication(timestampId));
				for (XmlConstraint constraint : constraints) {
					if (Utils.isStringNotEmpty(constraint.getId()) && constraint.getId().contains(timestampId)) {
						assertEquals(XmlStatus.OK, constraint.getStatus());
						basicValidationTSTFailedCounter++;
					}
				}
			}
			assertEquals(Indication.PASSED, detailedReport.getBasicBuildingBlocksIndication(timestampId));
			assertNull(detailedReport.getBasicBuildingBlocksSubIndication(timestampId));
		}
		assertEquals(2, basicValidationTSTFailedCounter);

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
		assertEquals(SignatureQualification.INDETERMINATE_QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

		List<Message> errors = simpleReport.getErrors(simpleReport.getFirstSignatureId());
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
		
		assertEquals(0, simpleReport.getErrors(simpleReport.getFirstSignatureId()).size());
		assertEquals(2, simpleReport.getWarnings(simpleReport.getFirstSignatureId()).size());

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

		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks basicBuildingBlockSigTimestamp = detailedReport
				.getBasicBuildingBlockById("T-B40B46167579BA169C72C8EA45F4316382614B5034B23114BFD160E3CED8CD68");
		assertNotNull(basicBuildingBlockSigTimestamp);
		assertEquals(Indication.FAILED, basicBuildingBlockSigTimestamp.getConclusion().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, basicBuildingBlockSigTimestamp.getConclusion().getSubIndication());

		SimpleReport simpleReport = reports.getSimpleReport();
		// Sig TST + archival TST are broken -> unable to process the past signature
		// validation + POE extraction
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.INDETERMINATE_ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

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
		// reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.INDETERMINATE_QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		
		Date timestampProductionDate = diagnosticData.getSignatures().get(0).getFoundTimestamps().get(0).getTimestamp().getProductionTime();
		Date bestSignatureTime = simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId());
		assertEquals(timestampProductionDate, bestSignatureTime);

		List<Message> errors = simpleReport.getErrors(simpleReport.getFirstSignatureId());
		assertEquals(7, errors.size());

		validateBestSigningTimes(reports);
		checkReports(reports);
	}

	@Test
	public void testDSS1686noPOE() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-1686/dss-1686-noPOE.xml"));
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
		assertEquals(SignatureQualification.INDETERMINATE_ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		
		Date validationDate = diagnosticData.getValidationDate();
		Date bestSignatureTime = simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId());
		assertEquals(validationDate, bestSignatureTime);

		List<Message> errors = simpleReport.getErrors(simpleReport.getFirstSignatureId());
		assertEquals(6, errors.size());
		

		DetailedReport detailedReport = reports.getDetailedReport();
		
		XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getSignatures().get(0).getValidationProcessArchivalData();
		
		List<XmlConstraint> constraints = validationProcessArchivalData.getConstraint();
		
		List<String> timestampIds = detailedReport.getTimestampIds();
		int basicValidationTSTFailedCounter = 0;
		for (String timestampId : timestampIds) {
			Indication timestampValidationIndication = detailedReport.getTimestampValidationIndication(timestampId);
			if (!Indication.PASSED.equals(timestampValidationIndication)) {
				assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getTimestampValidationSubIndication(timestampId));
				for (XmlConstraint constraint : constraints) {
					if (Utils.isStringNotEmpty(constraint.getId()) && constraint.getId().contains(timestampId)) {
						assertEquals(XmlStatus.WARNING, constraint.getStatus());
						basicValidationTSTFailedCounter++;
					}
				}
			}
			assertEquals(Indication.INDETERMINATE, detailedReport.getBasicBuildingBlocksIndication(timestampId));
			assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicBuildingBlocksSubIndication(timestampId));
		}
		assertEquals(1, basicValidationTSTFailedCounter);

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

		List<Message> warnings = simpleReport.getWarnings(simpleReport.getFirstSignatureId());
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

		List<Message> errors = simpleReport.getErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_CV_IAFS_ANS)));

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
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.INDETERMINATE_QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

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
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.INDETERMINATE_QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

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
		// reports.print();
		assertNotNull(reports);

		// Expiration of the OCSP Responder should not change the validation result
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		
		// cert is not TSA/QTST
		assertEquals(1, simpleReport.getErrors(simpleReport.getFirstSignatureId()).size());

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
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
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

		assertEquals(Indication.PASSED, detailedReport.getTimestampValidationIndication(timestampIds.get(0)));

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
			assertEquals(Indication.PASSED, detailedReport.getTimestampValidationIndication(tspId));
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
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureBBB);
		
		XmlXCV xcv = signatureBBB.getXCV();
		assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		assertEquals(SubIndication.TRY_LATER, xcv.getConclusion().getSubIndication());
		
		XmlSubXCV xmlSubXCV = xcv.getSubXCV().get(0);
		assertNotNull(xmlSubXCV);
		List<XmlRAC> xmlRACs = xmlSubXCV.getRAC();
		assertEquals(1, xmlRACs.size());
		XmlRAC xmlRAC = xmlRACs.get(0);
		assertEquals(Indication.INDETERMINATE, xmlRAC.getConclusion().getIndication());
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, xmlRAC.getConclusion().getSubIndication());
		
		XmlRFC rfc = xmlSubXCV.getRFC();
		assertNotNull(rfc);
		List<XmlConstraint> rfcConstraints = rfc.getConstraint();
		assertEquals(1, rfcConstraints.size());
		XmlConstraint constraint = rfcConstraints.get(0);
		assertEquals(MessageTag.BBB_XCV_IARDPFC.name(), constraint.getName().getKey());
		assertEquals(i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS), constraint.getError().getValue());
		assertEquals(Indication.INDETERMINATE, rfc.getConclusion().getIndication());
		assertEquals(SubIndication.TRY_LATER, rfc.getConclusion().getSubIndication());
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
		assertEquals(SubIndication.NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_CA_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));
		
		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_CA_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));
		
		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_POE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));
		
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

		List<Message> warnings = simpleReport.getWarnings(simpleReport.getFirstSignatureId());
		assertFalse(checkMessageValuePresence(warnings, i18nProvider.getMessage(MessageTag.TSV_ASTPTCT_ANS)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		List<String> timestampIds = detailedReport.getTimestampIds();
		assertEquals(5, timestampIds.size());
		for (String tspId : timestampIds) {
			assertEquals(Indication.PASSED, detailedReport.getTimestampValidationIndication(tspId));
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
			assertEquals(Indication.PASSED, detailedReport.getTimestampValidationIndication(tspId));
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

		assertTrue(checkMessageValuePresence(simpleReport.getErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.LTV_ABSV_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getErrors(simpleReport.getFirstSignatureId()),
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
	public void signingCertificateNotFound() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/signing_certificate_not_found.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
		Date currentTime = sdf.parse("04/05/2016 15:55:00");
		executor.setCurrentTime(currentTime);

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(0, detailedReport.getTimestampIds().size());

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));

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
		checkReports(executor.execute());

		executor.setValidationLevel(ValidationLevel.TIMESTAMPS);
		checkReports(executor.execute());

		executor.setValidationLevel(ValidationLevel.LONG_TERM_DATA);
		checkReports(executor.execute());

		executor.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
		checkReports(executor.execute());
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
			XmlCryptographicInformation cryptographicInfo = sav.getCryptographicInfo();
			if (!cryptographicInfo.isSecure()) {
				foundWeakAlgo = true;
				assertTrue(validationDate.after(cryptographicInfo.getNotAfter()));
			}
		}
		assertTrue(foundWeakAlgo);
		
		SimpleReport simpleReport = reports.getSimpleReport();
		
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicBuildingBlocksIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_POE, detailedReport.getBasicBuildingBlocksSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_POE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));

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

		//Get the Error Message as well as any extra information
		XmlSAV sav = basicBuildingBlockById.getSAV();
		XmlConstraint xmlConstraint = sav.getConstraint().get(0);
		XmlMessage error = xmlConstraint.getError();
		
		assertEquals(MessageTag.ASCCM_PKSK_ANS.name(), error.getKey());

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId())); // OCSP Cert not found

		executor.setValidationLevel(ValidationLevel.LONG_TERM_DATA);
		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId())); // OCSP Cert not found

		executor.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);
		reports = executor.execute();
		simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId())); // Crypto for OCSP
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
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
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
		
		List<Message> errors = simpleReport.getErrors(firstSigId);
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
		
		List<Message> errors = simpleReport.getErrors(secondSigId);
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
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SignatureQualification.NA, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

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
		assertEquals(SignatureQualification.ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		
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
		assertEquals(SubIndication.NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		TimestampWrapper earliestTimestamp = reports.getDiagnosticData().getTimestampById("T-950D06E9BC8B0CDB73D88349F14D3BC702BF4947752A121A940EE03639C1249D");
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		ValidationObjectListType signatureValidationObjects = etsiValidationReport.getSignatureValidationObjects();
		assertNotNull(signatureValidationObjects);
		assertTrue(Utils.isCollectionNotEmpty(signatureValidationObjects.getValidationObject()));
		for (ValidationObjectType validationObject : signatureValidationObjects.getValidationObject()) {
			if (validationObject.getPOE() != null) {
				VOReferenceType poeObjectReference = validationObject.getPOE().getPOEObject();
				if (poeObjectReference != null) {
					assertEquals(earliestTimestamp.getProductionTime(), validationObject.getPOE().getPOETime());
					Object poeObject = poeObjectReference.getVOReference().get(0);
					assertTrue(poeObject instanceof ValidationObjectType);
					assertEquals(earliestTimestamp.getId(), ((ValidationObjectType) poeObject).getId());
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
		
		List<Message> warnings = simpleReport.getWarnings(simpleReport.getFirstSignatureId());
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
		
		List<Message> errors = simpleReport.getErrors(simpleReport.getFirstSignatureId());
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
		
		List<Message> warnings = simpleReport.getWarnings(simpleReport.getFirstSignatureId());
		assertEquals(1, warnings.size());
		assertEquals(i18nProvider.getMessage(MessageTag.BBB_SAV_ISQPMDOSPP_ANS), warnings.get(0).getValue());
		
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
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));
	}
	
	@Test
	public void expiredCertsRevocationInfoTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/expired-certs-revocation-info.xml"));
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
	public void expiredCertsOnCRLExtension() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/expired-certs-on-crl-extension.xml"));
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
			List<BigInteger> byteRange = pdfSignatureDictionary.getSignatureByteRange();
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
		List<BigInteger> xmlByteRange = xmlSignatures.get(0).getPDFRevision().getPDFSignatureDictionary().getSignatureByteRange();
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
		assertEquals(SubIndication.NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

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
		assertEquals(SubIndication.NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		checkReports(reports);
		
	}
	
	@Test
	public void dss1635Test() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/dss-1635-diag-data.xml"));
		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		ValidationPolicy defaultPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
		List<Algo> algos = defaultPolicy.getCryptographic().getAlgoExpirationDate().getAlgo();
		for (Algo algo : algos) {
			if ("SHA1".equals(algo.getValue())) {
				algo.setDate("2014");
				break;
			}
		}
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(new Date());

		Reports reports = executor.execute();
		// reports.print();
		
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
		assertFalse(sav.getCryptographicInfo().isSecure());
		
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
		assertTrue(Arrays.equals(signatureDigestReference.getDigestValue(), signatureReferenceType.getDigestValue()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlSAV sav = signatureBBB.getSAV();
		assertEquals(1, sav.getConclusion().getErrors().size());
		
		XmlCryptographicInformation cryptographicInfo = sav.getCryptographicInfo();
		assertEquals(SignatureAlgorithm.RSA_SHA1, SignatureAlgorithm.forXML(cryptographicInfo.getAlgorithm()));
		assertEquals("2048", cryptographicInfo.getKeyLength());
		
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
		
		List<Message> warnings = simpleReport.getWarnings(simpleReport.getFirstSignatureId());
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
			
			List<Message> errors = simpleReport.getErrors(signatureId);
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
			
			List<Message> warnings = simpleReport.getWarnings(signatureId);
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
			
			List<Message> errors = simpleReport.getErrors(signatureId);
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
			
			List<Message> warnings = simpleReport.getWarnings(signatureId);
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

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
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
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();
		 
		List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
		assertEquals(1, usedTimestamps.size());
		String tstId = usedTimestamps.get(0).getId();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getTimestampValidationIndication(tstId));
		assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, detailedReport.getTimestampValidationSubIndication(tstId));
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
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		// reports.print();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void dss2025AnotherCertSignCertRef() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/DSS-2025/diag-sign-cert-another-cert.xml"));
		assertNotNull(diagnosticData);

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
		// reports.print();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
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
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
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
		
		List<Message> errors = simpleReport.getErrors(simpleReport.getFirstSignatureId());
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
		
		List<Message> errors = simpleReport.getErrors(simpleReport.getFirstSignatureId());
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
		
		List<Message> errors = simpleReport.getErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_XCV_REVOC_PRES_ANS)));
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
		
		List<Message> errors = simpleReport.getErrors(simpleReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(errors,
				i18nProvider.getMessage(MessageTag.BBB_XCV_ISCGCOUN_ANS)));
	}
	
	@Test
	public void noAIATest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/valid-diag-data.xml"));
		assertNotNull(diagnosticData);
		
		XmlSigningCertificate signingCertificate = diagnosticData.getSignatures().get(0).getSigningCertificate();
		signingCertificate.getCertificate().getAuthorityInformationAccessUrls().clear();

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
		
		List<Message> errors = simpleReport.getErrors(simpleReport.getFirstSignatureId());
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
		assertEquals(Indication.PASSED, detailedReport.getTimestampValidationIndication(tstId));
		
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlSAV sav = signatureBBB.getSAV();
		assertEquals(1, sav.getConclusion().getErrors().size());
		
		XmlCryptographicInformation cryptographicInfo = sav.getCryptographicInfo();
		assertEquals(DigestAlgorithm.SHA1, DigestAlgorithm.forXML(cryptographicInfo.getAlgorithm()));		
		
		List<Message> errors = simpleReport.getErrors(simpleReport.getFirstSignatureId());
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
		assertEquals(Indication.INDETERMINATE, detailedReport.getTimestampValidationIndication(xmlTimestamp.getId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getTimestampValidationSubIndication(xmlTimestamp.getId()));
		
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
		XmlSAV sav = signatureBBB.getSAV();
		assertEquals(1, sav.getConclusion().getErrors().size());
		
		XmlCryptographicInformation cryptographicInfo = sav.getCryptographicInfo();
		assertEquals(DigestAlgorithm.SHA1, DigestAlgorithm.forXML(cryptographicInfo.getAlgorithm()));		
		
		List<Message> errors = simpleReport.getErrors(simpleReport.getFirstSignatureId());
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
		
		boolean zeroHashPolicyCheckExecuted = false;
		for (XmlConstraint constraint : vci.getConstraint()) {
			if (MessageTag.BBB_VCI_IZHSP.name().equals(constraint.getName().getKey())) {
				zeroHashPolicyCheckExecuted = true;
			}
			assertEquals(XmlStatus.OK, constraint.getStatus());
		}
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
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
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
		assertEquals(SignatureQualification.NA, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

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
		for (XmlRAC rac : xcv.getSubXCV().get(0).getRAC()) {
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
		assertFalse(checkMessageValuePresence(simpleReport.getErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDC_ANS)));
		assertFalse(checkMessageValuePresence(simpleReport.getWarnings(simpleReport.getFirstSignatureId()),
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
			assertEquals(SubIndication.TRY_LATER, detailedReport.getBasicBuildingBlocksSubIndication(xmlRevocation.getId()));
			assertEquals(2, detailedReport.getErrors(xmlRevocation.getId()).size());
			assertEquals(1, detailedReport.getWarnings(xmlRevocation.getId()).size());
			assertEquals(0, detailedReport.getInfos(xmlRevocation.getId()).size());

			XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(xmlRevocation.getId());
			assertEquals(2, bbb.getConclusion().getErrors().size());
			assertEquals(1, bbb.getConclusion().getWarnings().size());
			assertEquals(0, bbb.getConclusion().getInfos().size());

			XmlXCV xcv = bbb.getXCV();
			assertNotNull(xcv);
			assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
			assertEquals(SubIndication.TRY_LATER, xcv.getConclusion().getSubIndication());
			assertEquals(2, xcv.getConclusion().getErrors().size());
			assertEquals(1, xcv.getConclusion().getWarnings().size());
			assertEquals(0, xcv.getConclusion().getInfos().size());

			boolean failedSubXCVFound = false;
			for (XmlSubXCV subXCV : xcv.getSubXCV()){
				if (Indication.INDETERMINATE.equals(subXCV.getConclusion().getIndication())) {
					assertEquals(SubIndication.TRY_LATER, subXCV.getConclusion().getSubIndication());
					assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()),
							i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
					assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()),
							i18nProvider.getMessage(MessageTag.BBB_XCV_OCSP_NO_CHECK_ANS)));
					failedSubXCVFound = true;
				}
			}
			assertTrue(failedSubXCVFound);

			assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()),
					i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
			assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getWarnings()),
					i18nProvider.getMessage(MessageTag.BBB_XCV_OCSP_NO_CHECK_ANS)));

			assertTrue(checkMessageValuePresence(detailedReport.getErrors(xmlRevocation.getId()),
					i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
			assertTrue(checkMessageValuePresence(detailedReport.getWarnings(xmlRevocation.getId()),
					i18nProvider.getMessage(MessageTag.BBB_XCV_OCSP_NO_CHECK_ANS)));
		}

		assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, detailedReport.getFinalSubIndication(detailedReport.getFirstSignatureId()));
		assertTrue(checkMessageValuePresence(detailedReport.getErrors(detailedReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
		assertTrue(checkMessageValuePresence(detailedReport.getWarnings(detailedReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_OCSP_NO_CHECK_ANS)));

		XmlConstraintsConclusion highestConclusion = detailedReport.getHighestConclusion(detailedReport.getFirstSignatureId());
		assertTrue(checkMessageValuePresence(convert(highestConclusion.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.ARCH_LTVV_ANS)));
		assertFalse(checkMessageValuePresence(convert(highestConclusion.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
		assertFalse(checkMessageValuePresence(convert(highestConclusion.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_OCSP_NO_CHECK_ANS)));

		SimpleReport simpleReport = reports.getSimpleReport();
		assertTrue(checkMessageValuePresence(simpleReport.getErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getWarnings(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.BBB_XCV_OCSP_NO_CHECK_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getErrors(simpleReport.getFirstSignatureId()),
				i18nProvider.getMessage(MessageTag.ARCH_LTVV_ANS)));

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
		return defaultPolicy;
	}

}
