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
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalDataTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationTimestampQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationTimestampQualificationAtTime;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TimestampAloneValidationTest extends AbstractTestValidationExecutor {

	private static I18nProvider i18nProvider;

	@BeforeAll
	public static void init() {
		i18nProvider = new I18nProvider(Locale.getDefault());
	}

	@Test
	public void qtsa() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/timestamp-validation/qtsa.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());

		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(TimestampQualification.QTSA, simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(TimestampQualification.QTSA, detailedReport.getTimestampQualificationAtTstGenerationTime(detailedReport.getFirstTimestampId()));
		assertEquals(TimestampQualification.QTSA, detailedReport.getTimestampQualificationAtBestPoeTime(detailedReport.getFirstTimestampId()));

		checkReports(reports);
	}

	@Test
	public void tsa() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/timestamp-validation/tsa.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(TimestampQualification.TSA, simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(TimestampQualification.TSA, detailedReport.getTimestampQualificationAtTstGenerationTime(detailedReport.getFirstTimestampId()));
		assertEquals(TimestampQualification.TSA, detailedReport.getTimestampQualificationAtBestPoeTime(detailedReport.getFirstTimestampId()));

		checkReports(reports);
	}

	@Test
	public void expiredTsa() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/timestamp-validation/expired-tsa.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(TimestampQualification.TSA, simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId()));

		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstTimestampId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstTimestampId()));

		checkReports(reports);
	}

	@Test
	public void expiredTsaAndHashFailure() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
				.unmarshall(new File("src/test/resources/diag-data/timestamp-validation/expired-tsa-and-hash-failure.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(TimestampQualification.TSA, simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId()));

		assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstTimestampId()));
		assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstTimestampId()));

		checkReports(reports);
	}

	@Test
	public void na() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/timestamp-validation/na.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(TimestampQualification.NA, simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(0, detailedReport.getSignatures().size());
		assertEquals(1, detailedReport.getIndependentTimestamps().size());

		checkReports(reports);
	}

	@Test
	public void sigAndTst() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/timestamp-validation/sig-and-tst.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();

//		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(TimestampQualification.NA, simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(2, detailedReport.getSignatures().size());
		assertEquals(2, detailedReport.getIndependentTimestamps().size());

		checkReports(reports);
	}

	@Test
	public void sigAndTst2() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/timestamp-validation/sig-and-tst2.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();

//		reports.print();	

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(1, detailedReport.getSignatures().size());
		XmlSignature xmlSignature = detailedReport.getSignatures().get(0);
		assertEquals(0, detailedReport.getIndependentTimestamps().size());
		assertEquals(2, xmlSignature.getTimestamps().size());

		checkReports(reports);
	}

	@Test
	public void diffResultQualAtGenTimeTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag-data/timestamp-validation/tsa-diff-qual-at-gen-time.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(TimestampQualification.TSA, simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId()));
		assertFalse(Utils.isCollectionEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstTimestampId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstTimestampId()),
				i18nProvider.getMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(TimestampQualification.TSA, detailedReport.getTimestampQualification(detailedReport.getFirstTimestampId()));
		assertEquals(TimestampQualification.QTSA, detailedReport.getTimestampQualificationAtTstGenerationTime(detailedReport.getFirstTimestampId()));
		assertEquals(TimestampQualification.TSA, detailedReport.getTimestampQualificationAtBestPoeTime(detailedReport.getFirstTimestampId()));

		XmlTimestamp xmlTimestamp = detailedReport.getXmlTimestampById(detailedReport.getFirstTimestampId());
		assertNotNull(xmlTimestamp);

		XmlValidationTimestampQualification validationTimestampQualification = xmlTimestamp.getValidationTimestampQualification();
		assertEquals(TimestampQualification.TSA, validationTimestampQualification.getTimestampQualification());
		assertFalse(Utils.isCollectionEmpty(validationTimestampQualification.getConclusion().getErrors()));
		assertTrue(checkMessageValuePresence(convert(validationTimestampQualification.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)));

		assertTrue(Utils.isCollectionNotEmpty(validationTimestampQualification.getConstraint()));
		for (XmlConstraint constraint : validationTimestampQualification.getConstraint()) {
			assertEquals(XmlStatus.OK, constraint.getStatus());
		}

		List<XmlValidationTimestampQualificationAtTime> validationTimestampQualificationAtTime = validationTimestampQualification.getValidationTimestampQualificationAtTime();
		assertEquals(2, validationTimestampQualificationAtTime.size());

		boolean tstQualValidationAtGenTimeFound = false;
		boolean tstQualValidationAtBestPoeTimeFound = false;
		for (XmlValidationTimestampQualificationAtTime tstQualAtTime : validationTimestampQualificationAtTime) {
			if (ValidationTime.TIMESTAMP_GENERATION_TIME.equals(tstQualAtTime.getValidationTime())) {
				assertEquals(TimestampQualification.QTSA, tstQualAtTime.getTimestampQualification());
				assertTrue(Utils.isCollectionEmpty(tstQualAtTime.getConclusion().getErrors()));
				boolean atGenTimeCheckFound = false;
				for (XmlConstraint constraint : tstQualAtTime.getConstraint()) {
					if (MessageTag.QUAL_HAS_GRANTED_AT.getId().equals(constraint.getName().getKey())) {
						assertEquals(i18nProvider.getMessage(MessageTag.QUAL_HAS_GRANTED_AT, MessageTag.VT_TST_GENERATION_TIME),
								constraint.getName().getValue());
						atGenTimeCheckFound = true;
					}
					assertEquals(XmlStatus.OK, constraint.getStatus());
				}
				assertTrue(atGenTimeCheckFound);
				tstQualValidationAtGenTimeFound = true;

			} else if (ValidationTime.TIMESTAMP_POE_TIME.equals(tstQualAtTime.getValidationTime())) {
				assertEquals(TimestampQualification.TSA, tstQualAtTime.getTimestampQualification());
				assertFalse(Utils.isCollectionEmpty(tstQualAtTime.getConclusion().getErrors()));
				assertTrue(checkMessageValuePresence(convert(tstQualAtTime.getConclusion().getErrors()),
						i18nProvider.getMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_POE_TIME)));
				boolean grantedAtTimeCheckFound = false;
				for (XmlConstraint constraint : tstQualAtTime.getConstraint()) {
					if (MessageTag.QUAL_HAS_GRANTED_AT.getId().equals(constraint.getName().getKey())) {
						assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
						assertEquals(MessageTag.QUAL_HAS_GRANTED_AT_ANS.getId(), constraint.getError().getKey());
						grantedAtTimeCheckFound = true;
					} else {
						assertEquals(XmlStatus.OK, constraint.getStatus());
					}
				}
				assertTrue(grantedAtTimeCheckFound);
				tstQualValidationAtBestPoeTimeFound = true;
			}
		}
		assertTrue(tstQualValidationAtGenTimeFound);
		assertTrue(tstQualValidationAtBestPoeTimeFound);

		checkReports(reports);
	}

	@Test
	public void diffResultQualAtPoeTimeTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag-data/timestamp-validation/tsa-diff-qual-at-poe-time.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(TimestampQualification.TSA, simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId()));
		assertFalse(Utils.isCollectionEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstTimestampId())));
		assertTrue(checkMessageValuePresence(simpleReport.getQualificationErrors(simpleReport.getFirstTimestampId()),
				i18nProvider.getMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_GENERATION_TIME)));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(TimestampQualification.TSA, detailedReport.getTimestampQualification(detailedReport.getFirstTimestampId()));
		assertEquals(TimestampQualification.TSA, detailedReport.getTimestampQualificationAtTstGenerationTime(detailedReport.getFirstTimestampId()));
		assertEquals(TimestampQualification.QTSA, detailedReport.getTimestampQualificationAtBestPoeTime(detailedReport.getFirstTimestampId()));

		XmlTimestamp xmlTimestamp = detailedReport.getXmlTimestampById(detailedReport.getFirstTimestampId());
		assertNotNull(xmlTimestamp);

		XmlValidationTimestampQualification validationTimestampQualification = xmlTimestamp.getValidationTimestampQualification();
		assertEquals(TimestampQualification.TSA, validationTimestampQualification.getTimestampQualification());
		assertFalse(Utils.isCollectionEmpty(validationTimestampQualification.getConclusion().getErrors()));
		assertTrue(checkMessageValuePresence(convert(validationTimestampQualification.getConclusion().getErrors()),
				i18nProvider.getMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_GENERATION_TIME)));

		assertTrue(Utils.isCollectionNotEmpty(validationTimestampQualification.getConstraint()));
		for (XmlConstraint constraint : validationTimestampQualification.getConstraint()) {
			assertEquals(XmlStatus.OK, constraint.getStatus());
		}

		List<XmlValidationTimestampQualificationAtTime> validationTimestampQualificationAtTime = validationTimestampQualification.getValidationTimestampQualificationAtTime();
		assertEquals(2, validationTimestampQualificationAtTime.size());

		boolean tstQualValidationAtGenTimeFound = false;
		boolean tstQualValidationAtBestPoeTimeFound = false;
		for (XmlValidationTimestampQualificationAtTime tstQualAtTime : validationTimestampQualificationAtTime) {
			if (ValidationTime.TIMESTAMP_GENERATION_TIME.equals(tstQualAtTime.getValidationTime())) {
				assertEquals(TimestampQualification.TSA, tstQualAtTime.getTimestampQualification());
				assertFalse(Utils.isCollectionEmpty(tstQualAtTime.getConclusion().getErrors()));
				assertTrue(checkMessageValuePresence(convert(tstQualAtTime.getConclusion().getErrors()),
						i18nProvider.getMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, MessageTag.VT_TST_GENERATION_TIME)));
				boolean grantedAtTimeCheckFound = false;
				for (XmlConstraint constraint : tstQualAtTime.getConstraint()) {
					if (MessageTag.QUAL_HAS_GRANTED_AT.getId().equals(constraint.getName().getKey())) {
						assertEquals(i18nProvider.getMessage(MessageTag.QUAL_HAS_GRANTED_AT, MessageTag.VT_TST_GENERATION_TIME),
								constraint.getName().getValue());
						assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
						assertEquals(MessageTag.QUAL_HAS_GRANTED_AT_ANS.getId(), constraint.getError().getKey());
						grantedAtTimeCheckFound = true;
					} else {
						assertEquals(XmlStatus.OK, constraint.getStatus());
					}
				}
				assertTrue(grantedAtTimeCheckFound);

				tstQualValidationAtGenTimeFound = true;
			} else if (ValidationTime.TIMESTAMP_POE_TIME.equals(tstQualAtTime.getValidationTime())) {
				assertEquals(TimestampQualification.QTSA, tstQualAtTime.getTimestampQualification());
				assertTrue(Utils.isCollectionEmpty(tstQualAtTime.getConclusion().getErrors()));
				boolean atPoeTimeCheckFound = false;
				for (XmlConstraint constraint : tstQualAtTime.getConstraint()) {
					if (MessageTag.QUAL_HAS_GRANTED_AT.getId().equals(constraint.getName().getKey())) {
						assertEquals(i18nProvider.getMessage(MessageTag.QUAL_HAS_GRANTED_AT, MessageTag.VT_TST_POE_TIME), constraint.getName().getValue());
						atPoeTimeCheckFound = true;
					}
					assertEquals(XmlStatus.OK, constraint.getStatus());
				}
				assertTrue(atPoeTimeCheckFound);
				tstQualValidationAtBestPoeTimeFound = true;
			}
		}
		assertTrue(tstQualValidationAtGenTimeFound);
		assertTrue(tstQualValidationAtBestPoeTimeFound);

		checkReports(reports);
	}

	@Test
	public void twoTstPastValidationTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag-data/timestamp-validation/two-tst-past-val.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		List<String> timestampIdList = simpleReport.getTimestampIdList();
		assertEquals(2, timestampIdList.size());

		assertEquals(Indication.PASSED, simpleReport.getIndication(timestampIdList.get(0)));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(timestampIdList.get(0))));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(timestampIdList.get(0))));
		assertEquals(Indication.PASSED, simpleReport.getIndication(timestampIdList.get(1)));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(timestampIdList.get(1))));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(timestampIdList.get(1))));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(0, detailedReport.getSignatures().size());
		assertEquals(2, detailedReport.getIndependentTimestamps().size());

		List<String> timestampIds = detailedReport.getTimestampIds();

		assertEquals(Indication.PASSED, detailedReport.getFinalIndication(timestampIds.get(0)));
		assertTrue(Utils.isCollectionEmpty(detailedReport.getAdESValidationErrors(timestampIds.get(0))));

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(timestampIds.get(0)));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicTimestampValidationSubIndication(timestampIds.get(0)));

		assertEquals(Indication.PASSED, detailedReport.getArchiveDataTimestampValidationIndication(timestampIds.get(0)));

		XmlTimestamp xmlTimestamp = detailedReport.getXmlTimestampById(timestampIds.get(0));
		XmlValidationProcessBasicTimestamp tstBasic = xmlTimestamp.getValidationProcessBasicTimestamp();
		assertEquals(Indication.INDETERMINATE, tstBasic.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, tstBasic.getConclusion().getSubIndication());
		assertTrue(checkMessageValuePresence(convert(tstBasic.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_SUB_ANS)));
		assertTrue(checkMessageValuePresence(convert(tstBasic.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));

		XmlValidationProcessArchivalDataTimestamp timestampArchivalData = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
		assertEquals(Indication.PASSED, timestampArchivalData.getConclusion().getIndication());
		assertTrue(Utils.isCollectionEmpty(timestampArchivalData.getConclusion().getErrors()));

		boolean tstBasicAcceptableFound = false;
		boolean tstBasicConclusiveFound = false;
		boolean tstPastSigFound = false;
		for (XmlConstraint constraint : timestampArchivalData.getConstraint()) {
			if (MessageTag.ARCH_IRTVBBA.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				tstBasicAcceptableFound = true;
			} else if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
				tstBasicConclusiveFound = true;
			} else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				tstPastSigFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(tstBasicAcceptableFound);
		assertTrue(tstBasicConclusiveFound);
		assertTrue(tstPastSigFound);

		assertEquals(Indication.PASSED, detailedReport.getFinalIndication(timestampIds.get(1)));
		assertTrue(Utils.isCollectionEmpty(detailedReport.getAdESValidationErrors(timestampIds.get(1))));
		assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(timestampIds.get(1)));
		assertEquals(Indication.PASSED, detailedReport.getArchiveDataTimestampValidationIndication(timestampIds.get(1)));

		xmlTimestamp = detailedReport.getXmlTimestampById(timestampIds.get(1));
		tstBasic = xmlTimestamp.getValidationProcessBasicTimestamp();
		assertEquals(Indication.PASSED, tstBasic.getConclusion().getIndication());
		assertTrue(Utils.isCollectionEmpty(tstBasic.getConclusion().getErrors()));

		timestampArchivalData = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
		assertEquals(Indication.PASSED, timestampArchivalData.getConclusion().getIndication());
		assertTrue(Utils.isCollectionEmpty(timestampArchivalData.getConclusion().getErrors()));

		tstBasicAcceptableFound = false;
		tstBasicConclusiveFound = false;
		tstPastSigFound = false;
		for (XmlConstraint constraint : timestampArchivalData.getConstraint()) {
			if (MessageTag.ARCH_IRTVBBA.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				tstBasicAcceptableFound = true;
			} else if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				tstBasicConclusiveFound = true;
			} else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
				tstPastSigFound = true;
			} else {
				assertEquals(XmlStatus.OK, constraint.getStatus());
			}
		}
		assertTrue(tstBasicAcceptableFound);
		assertTrue(tstBasicConclusiveFound);
		assertFalse(tstPastSigFound);

		checkReports(reports);
	}

	@Test
	public void twoTstTimestampOnlyValidationTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag-data/timestamp-validation/two-tst-past-val.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setValidationLevel(ValidationLevel.TIMESTAMPS);
		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		List<String> timestampIdList = simpleReport.getTimestampIdList();
		assertEquals(2, timestampIdList.size());

		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(timestampIdList.get(0)));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(timestampIdList.get(0)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(timestampIdList.get(0)),
				i18nProvider.getMessage(MessageTag.BBB_XCV_SUB_ANS)));
		assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(timestampIdList.get(0)),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(timestampIdList.get(0))));

		assertEquals(Indication.PASSED, simpleReport.getIndication(timestampIdList.get(1)));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(timestampIdList.get(1))));
		assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(timestampIdList.get(1))));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(0, detailedReport.getSignatures().size());
		assertEquals(2, detailedReport.getIndependentTimestamps().size());

		List<String> timestampIds = detailedReport.getTimestampIds();

		assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(timestampIds.get(0)));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getFinalSubIndication(timestampIds.get(0)));
		assertTrue(checkMessageValuePresence(detailedReport.getAdESValidationErrors(timestampIds.get(0)),
				i18nProvider.getMessage(MessageTag.BBB_XCV_SUB_ANS)));
		assertTrue(checkMessageValuePresence(detailedReport.getAdESValidationErrors(timestampIds.get(0)),
				i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));

		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(timestampIds.get(0)));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicTimestampValidationSubIndication(timestampIds.get(0)));

		assertNull(detailedReport.getArchiveDataTimestampValidationIndication(timestampIds.get(0)));

		XmlTimestamp xmlTimestamp = detailedReport.getXmlTimestampById(timestampIds.get(0));
		XmlValidationProcessBasicTimestamp tstBasic = xmlTimestamp.getValidationProcessBasicTimestamp();
		assertEquals(Indication.INDETERMINATE, tstBasic.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, tstBasic.getConclusion().getSubIndication());
		assertTrue(checkMessageValuePresence(convert(tstBasic.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_SUB_ANS)));
		assertTrue(checkMessageValuePresence(convert(tstBasic.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));

		XmlValidationProcessArchivalDataTimestamp timestampArchivalData = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
		assertNull(timestampArchivalData);

		assertEquals(Indication.PASSED, detailedReport.getFinalIndication(timestampIds.get(1)));
		assertTrue(Utils.isCollectionEmpty(detailedReport.getAdESValidationErrors(timestampIds.get(1))));
		assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(timestampIds.get(1)));
		assertNull(detailedReport.getArchiveDataTimestampValidationIndication(timestampIds.get(1)));

		xmlTimestamp = detailedReport.getXmlTimestampById(timestampIds.get(1));
		tstBasic = xmlTimestamp.getValidationProcessBasicTimestamp();
		assertEquals(Indication.PASSED, tstBasic.getConclusion().getIndication());
		assertTrue(Utils.isCollectionEmpty(tstBasic.getConclusion().getErrors()));

		timestampArchivalData = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
		assertNull(timestampArchivalData);

		checkReports(reports);
	}

	@Test
	public void twoTstsBasicValidationTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag-data/timestamp-validation/two-tst-past-val.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);
		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		List<String> timestampIdList = simpleReport.getTimestampIdList();
		assertEquals(0, timestampIdList.size());

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(0, detailedReport.getIndependentTimestamps().size());

		List<String> timestampIds = detailedReport.getTimestampIds();
		assertEquals(0, timestampIds.size());

		checkReports(reports);
	}

	@Test
	public void tstWithErValidationTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag-data/timestamp-validation/tst-and-er.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.PASSED, simpleReport.getIndication(diagnosticData.getUsedTimestamps().get(0).getId()));

		List<eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord> tstErs = simpleReport.getTimestampEvidenceRecords(simpleReport.getFirstTimestampId());
		assertEquals(1, tstErs.size());

		eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord tstEr = tstErs.get(0);
		assertEquals(Indication.PASSED, simpleReport.getIndication(tstEr.getId()));

		assertEquals(Indication.PASSED, simpleReport.getIndication(tstEr.getTimestamps().getTimestamp().get(0).getId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		
		List<XmlTimestamp> timestamps = detailedReport.getIndependentTimestamps();
		assertEquals(1, timestamps.size());

		XmlTimestamp xmlTimestamp = timestamps.get(0);
		assertEquals(Indication.PASSED, xmlTimestamp.getConclusion().getIndication());

		XmlValidationProcessBasicTimestamp validationProcessBasicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
		assertEquals(Indication.INDETERMINATE, validationProcessBasicTimestamp.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessBasicTimestamp.getConclusion().getSubIndication());

		List<XmlEvidenceRecord> evidenceRecords = xmlTimestamp.getEvidenceRecords();
		assertEquals(1, evidenceRecords.size());

		XmlEvidenceRecord xmlEvidenceRecord = evidenceRecords.get(0);
		assertEquals(Indication.PASSED, xmlEvidenceRecord.getConclusion().getIndication());

		List<XmlTimestamp> erTimestamps = xmlEvidenceRecord.getTimestamps();
		assertEquals(1, erTimestamps.size());

		XmlTimestamp erTimestamp = erTimestamps.get(0);
		assertEquals(Indication.PASSED, erTimestamp.getConclusion().getIndication());

		XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
		assertEquals(Indication.PASSED, validationProcessEvidenceRecord.getConclusion().getIndication());

		XmlValidationProcessArchivalDataTimestamp validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
		assertEquals(Indication.PASSED, validationProcessArchivalDataTimestamp.getConclusion().getIndication());

		boolean erValidationCheckFound = false;
		boolean basicTstValidationCheckFound = false;
		boolean pastTstValidationCheckFound = false;
		for (XmlConstraint constraint : validationProcessArchivalDataTimestamp.getConstraint()) {
			if (MessageTag.ADEST_IRERVPC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				erValidationCheckFound = true;
			} else if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
				basicTstValidationCheckFound = true;
			} else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.OK, constraint.getStatus());
				pastTstValidationCheckFound = true;
			}
		}
		assertTrue(erValidationCheckFound);
		assertTrue(basicTstValidationCheckFound);
		assertTrue(pastTstValidationCheckFound);

		checkReports(reports);
	}

	@Test
	public void tstWithErValidationInvalidTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag-data/timestamp-validation/tst-and-er.xml"));
		assertNotNull(diagnosticData);

		eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord xmlEvidenceRecord = diagnosticData.getEvidenceRecords().get(0);
		xmlEvidenceRecord.getDigestMatchers().get(1).setDataIntact(false);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(diagnosticData.getUsedTimestamps().get(0).getId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(diagnosticData.getUsedTimestamps().get(0).getId()));

		List<eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord> tstErs = simpleReport.getTimestampEvidenceRecords(simpleReport.getFirstTimestampId());
		assertEquals(1, tstErs.size());

		eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord tstEr = tstErs.get(0);
		assertEquals(Indication.FAILED, simpleReport.getIndication(tstEr.getId()));
		assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(tstEr.getId()));

		assertEquals(Indication.PASSED, simpleReport.getIndication(tstEr.getTimestamps().getTimestamp().get(0).getId()));

		DetailedReport detailedReport = reports.getDetailedReport();

		List<XmlTimestamp> timestamps = detailedReport.getIndependentTimestamps();
		assertEquals(1, timestamps.size());

		XmlTimestamp xmlTimestamp = timestamps.get(0);
		assertEquals(Indication.INDETERMINATE, xmlTimestamp.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xmlTimestamp.getConclusion().getSubIndication());

		XmlValidationProcessBasicTimestamp validationProcessBasicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
		assertEquals(Indication.INDETERMINATE, validationProcessBasicTimestamp.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessBasicTimestamp.getConclusion().getSubIndication());

		List<XmlEvidenceRecord> evidenceRecords = xmlTimestamp.getEvidenceRecords();
		assertEquals(1, evidenceRecords.size());

		XmlEvidenceRecord evidenceRecord = evidenceRecords.get(0);
		assertEquals(Indication.FAILED, evidenceRecord.getConclusion().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, evidenceRecord.getConclusion().getSubIndication());

		List<XmlTimestamp> erTimestamps = evidenceRecord.getTimestamps();
		assertEquals(1, erTimestamps.size());

		XmlTimestamp erTimestamp = erTimestamps.get(0);
		assertEquals(Indication.PASSED, erTimestamp.getConclusion().getIndication());

		XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = evidenceRecord.getValidationProcessEvidenceRecord();
		assertEquals(Indication.FAILED, validationProcessEvidenceRecord.getConclusion().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, validationProcessEvidenceRecord.getConclusion().getSubIndication());

		XmlValidationProcessArchivalDataTimestamp validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
		assertEquals(Indication.INDETERMINATE, validationProcessArchivalDataTimestamp.getConclusion().getIndication());
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessArchivalDataTimestamp.getConclusion().getSubIndication());

		boolean erValidationCheckFound = false;
		boolean basicTstValidationCheckFound = false;
		boolean pastTstValidationCheckFound = false;
		for (XmlConstraint constraint : validationProcessArchivalDataTimestamp.getConstraint()) {
			if (MessageTag.ADEST_IRERVPC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.ADEST_IRERVPC_ANS.getId(), constraint.getWarning().getKey());
				erValidationCheckFound = true;
			} else if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.WARNING, constraint.getStatus());
				assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
				basicTstValidationCheckFound = true;
			} else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
				assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
				assertEquals(MessageTag.PSV_IPTVC_ANS.getId(), constraint.getError().getKey());
				pastTstValidationCheckFound = true;
			}
		}
		assertTrue(erValidationCheckFound);
		assertTrue(basicTstValidationCheckFound);
		assertTrue(pastTstValidationCheckFound);

		checkReports(reports);
	}

}
