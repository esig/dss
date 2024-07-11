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
package eu.europa.esig.dss.validation.executor.DSS2049;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationTimestampQualification;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.EIDAS;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.AbstractTestValidationExecutor;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS2049Test extends AbstractTestValidationExecutor {
	
	@Test
	void dss2049() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, true, true);
		Reports reports = execute(diagnosticData, Level.FAIL);
		assertValid(reports, SignatureQualification.QESIG, TimestampQualification.QTSA, true, true, true, MessageType.NONE, false);
	}
	
	@Test
	void lotlFailWithWarnLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(false, true, true);
		Reports reports = execute(diagnosticData, Level.WARN);
		assertValid(reports, SignatureQualification.QESIG, TimestampQualification.QTSA, true, true, true, MessageType.WARN, false);
	}
	
	@Test
	void lotlFailWithFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(false, true, true);
		Reports reports = execute(diagnosticData, Level.FAIL);
		assertValid(reports, SignatureQualification.NA, TimestampQualification.NA, false, false, false, MessageType.ERROR, false);
	}
	
	@Test
	void sigTlFailWithWarnLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, false, true);
		Reports reports = execute(diagnosticData, Level.WARN);
		assertValid(reports, SignatureQualification.QESIG, TimestampQualification.QTSA, true, true, true, MessageType.WARN, false);
	}
	
	@Test
	void sigTlFailWithFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, false, true);
		Reports reports = execute(diagnosticData, Level.FAIL);
		assertValid(reports, SignatureQualification.NA, TimestampQualification.QTSA, true, false, true, MessageType.ERROR, false);
	}
	
	@Test
	void tstTlFailWithWarnLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, true, false);
		Reports reports = execute(diagnosticData, Level.WARN);
		assertValid(reports, SignatureQualification.QESIG, TimestampQualification.QTSA, true, true, true, MessageType.WARN, true);
	}
	
	@Test
	void tstTlFailWithFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, true, false);
		Reports reports = execute(diagnosticData, Level.FAIL);
		assertValid(reports, SignatureQualification.QESIG, TimestampQualification.NA, true, true, false, MessageType.ERROR, true);
	}
	
	@Test
	void bothTlFailWithWarnLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, false, false);
		Reports reports = execute(diagnosticData, Level.WARN);
		assertValid(reports, SignatureQualification.QESIG, TimestampQualification.QTSA, true, true, true, MessageType.WARN, false);
	}
	
	@Test
	void bothTlFailWithFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, false, false);
		Reports reports = execute(diagnosticData, Level.FAIL);
		assertValid(reports, SignatureQualification.NA, TimestampQualification.NA, true, false, false, MessageType.ERROR, false);
	}
	
	private XmlDiagnosticData getDiagnosticData(boolean isLOTLWellSigned, boolean isSigTLWellSigned, boolean isTstTLWellSigned) throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag-data/DSS-2049/dss2049-diag-data.xml"));
		assertNotNull(diagnosticData);
		
		List<XmlTrustedList> trustedLists = diagnosticData.getTrustedLists();
		assertEquals(3, trustedLists.size());
		XmlTrustedList xmlLOTL = trustedLists.get(0);
		xmlLOTL.setWellSigned(isLOTLWellSigned);
		XmlTrustedList xmlSigTL = trustedLists.get(1);
		xmlSigTL.setWellSigned(isSigTLWellSigned);
		XmlTrustedList xmlTstTL = trustedLists.get(2);
		xmlTstTL.setWellSigned(isTstTLWellSigned);
		
		return diagnosticData;
	}
	
	private Reports execute(XmlDiagnosticData diagnosticData, Level tlWellSignedlLevel) throws Exception {
		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		
		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		EIDAS eidasConstraints = defaultPolicy.getEIDASConstraints();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(tlWellSignedlLevel);
		eidasConstraints.setTLWellSigned(levelConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		return executor.execute();
	}
	
	private void assertValid(Reports reports, SignatureQualification sigQual, TimestampQualification tstQual,
							 boolean assertLOTLValid, boolean assertSigTLValid, boolean assertTstTLValid,
							 MessageType expectedMessage, boolean tstConcerned) {
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(sigQual, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		
		switch (expectedMessage) {
			case NONE:
				if (tstConcerned) {
					assertTrue(Utils.isCollectionEmpty(simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())
							.get(0).getQualificationDetails().getWarning()));
					assertTrue(Utils.isCollectionEmpty(simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())
							.get(0).getQualificationDetails().getError()));
				} else {
					assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
					assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
				}
				break;
			case WARN:
				if (tstConcerned) {
					assertFalse(Utils.isCollectionEmpty(simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())
							.get(0).getQualificationDetails().getWarning()));
					assertTrue(Utils.isCollectionEmpty(simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())
							.get(0).getQualificationDetails().getError()));
				} else {
					assertFalse(Utils.isCollectionEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
					assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
				}
				break;
			case ERROR:
				if (tstConcerned) {
					assertFalse(Utils.isCollectionEmpty(simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())
							.get(0).getQualificationDetails().getWarning()));
					assertFalse(Utils.isCollectionEmpty(simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())
							.get(0).getQualificationDetails().getError()));
				} else {
					assertFalse(Utils.isCollectionEmpty(simpleReport.getQualificationWarnings(simpleReport.getFirstSignatureId())));
					assertFalse(Utils.isCollectionEmpty(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId())));
				}
			default:
				break;
		}
		
		DetailedReport detailedReport = reports.getDetailedReport();
		
		List<XmlSignature> signatures = detailedReport.getSignatures();
		assertEquals(1, signatures.size());
		XmlSignature xmlSignature = signatures.get(0);
		
		XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
		List<XmlConstraint> constraints = validationSignatureQualification.getConstraint();
		assertConstraintsValid(constraints, assertLOTLValid, assertSigTLValid, assertLOTLValid && assertSigTLValid);
		
		List<XmlTimestamp> timestamps = xmlSignature.getTimestamps();
		assertEquals(1, timestamps.size());
		XmlTimestamp xmlTimestamp = timestamps.get(0);
		
		assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(xmlTimestamp.getId()));
		assertEquals(tstQual, detailedReport.getTimestampQualification(xmlTimestamp.getId()));
		
		XmlValidationTimestampQualification validationTimestampQualification = xmlTimestamp.getValidationTimestampQualification();
		List<XmlConstraint> tstConstraints = validationTimestampQualification.getConstraint();
		assertConstraintsValid(tstConstraints, assertLOTLValid, assertTstTLValid, assertLOTLValid && assertTstTLValid);
	}
	
	private void assertConstraintsValid(List<XmlConstraint> constraints, boolean assertLOTLValid, boolean assertTLValid, boolean assertAcceptableFound) {
		int lotlsProcessed = 0;
		int tlsProcessed = 0;
		boolean isLOTLValid = false;
		boolean isTLValid = false;
		boolean acceptableFound = false;
		for (XmlConstraint constraint : constraints) {
			if (MessageTag.QUAL_LIST_OF_TRUSTED_LISTS_ACCEPT.name().equals(constraint.getName().getKey())) {
				++lotlsProcessed;
				if (XmlStatus.OK.equals(constraint.getStatus())) {
					isLOTLValid = true;
				}
			} else if (MessageTag.QUAL_TRUSTED_LIST_ACCEPT.name().equals(constraint.getName().getKey())) {
				++tlsProcessed;
				if (XmlStatus.OK.equals(constraint.getStatus())) {
					isTLValid = true;
				}
			} else if (MessageTag.QUAL_VALID_TRUSTED_LIST_PRESENT.name().equals(constraint.getName().getKey())) {
				if (XmlStatus.OK.equals(constraint.getStatus())) {
					acceptableFound = true;
				}
			}
		}
		assertEquals(1, lotlsProcessed);
		assertEquals(assertLOTLValid ? 1 : 0, tlsProcessed);
		assertEquals(assertLOTLValid, isLOTLValid);
		assertEquals(assertTLValid, isTLValid);
		assertEquals(assertAcceptableFound, acceptableFound);
	}
	
	enum MessageType {
		NONE, WARN, ERROR
	}

}
