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
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.TimestampConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS1861Test extends AbstractTestValidationExecutor {
	
	private EtsiValidationPolicy etsiValidationPolicy;
	
	@BeforeEach
	void init() throws Exception {
		File validationPolicyFile = new File("src/test/resources/diag-data/policy/default-only-constraint-policy.xml");
		ConstraintsParameters constraintsParameters = getConstraintsParameters(validationPolicyFile);
		
		TimestampConstraints timestamp = constraintsParameters.getTimestamp();
		LevelConstraint failLevelConstraint = new LevelConstraint();
		failLevelConstraint.setLevel(Level.FAIL);
		timestamp.setCoherence(failLevelConstraint);
		
		etsiValidationPolicy = new EtsiValidationPolicy(constraintsParameters);
	}
	
	@Test
	void test() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/DSS-1861/pades-timestamp-order-check.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(etsiValidationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		XmlSignature signatureValidation = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureValidation);
		
		XmlValidationProcessLongTermData validationProcessLongTermData = signatureValidation.getValidationProcessLongTermData();
		List<XmlConstraint> constraints = validationProcessLongTermData.getConstraint();
		assertTrue(Utils.isCollectionNotEmpty(constraints));
		
		boolean timestampCoherenceOrderCheckFound = false;
		for (XmlConstraint constraint : constraints) {
			if (MessageTag.TSV_ASTPTCT.getId().equals(constraint.getName().getKey())) {
				timestampCoherenceOrderCheckFound = XmlStatus.OK.equals(constraint.getStatus());
			}
		}
		assertTrue(timestampCoherenceOrderCheckFound);
	}
	
	@Test
	void wrongTimestampOrderTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/DSS-1861/pades-wrong-timestamp-order.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(etsiValidationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.TIMESTAMP_ORDER_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		XmlSignature signatureValidation = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureValidation);
		
		XmlValidationProcessLongTermData validationProcessLongTermData = signatureValidation.getValidationProcessLongTermData();
		List<XmlConstraint> constraints = validationProcessLongTermData.getConstraint();
		assertTrue(Utils.isCollectionNotEmpty(constraints));
		
		boolean timestampCoherenceOrderCheckFound = false;
		for (XmlConstraint constraint : constraints) {
			if (MessageTag.TSV_ASTPTCT.getId().equals(constraint.getName().getKey())) {
				timestampCoherenceOrderCheckFound = XmlStatus.NOT_OK.equals(constraint.getStatus());
			}
		}
		assertTrue(timestampCoherenceOrderCheckFound);
	}

}
