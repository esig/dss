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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;

public class TimestampAloneValidationTest extends AbstractTestValidationExecutor {

	@Test
	public void qtsa() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/timestamp-validation/qtsa.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(TimestampQualification.QTSA, simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId()));

		checkReports(reports);
	}

	@Test
	public void tsa() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/timestamp-validation/tsa.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(TimestampQualification.TSA, simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId()));

		checkReports(reports);
	}

	@Test
	public void expiredTsa() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/timestamp-validation/expired-tsa.xml"));
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
				.unmarshall(new File("src/test/resources/timestamp-validation/expired-tsa-and-hash-failure.xml"));
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
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/timestamp-validation/na.xml"));
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
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/timestamp-validation/sig-and-tst.xml"));
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
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/timestamp-validation/sig-and-tst2.xml"));
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

}
