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

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.certificate.DefaultCertificateProcessExecutor;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS1566Test extends AbstractTestValidationExecutor {
	
	@Test
	void test() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/dss1566-diagnostic.xml"));

		DefaultCertificateProcessExecutor executor = new DefaultCertificateProcessExecutor();
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setDiagnosticData(diagnosticData);
		executor.setCertificateId("C-D04D16660A6BA5FDD2C3A519DAD8877B64D1D2C56BF91316208A0AE2FB76D368");
		executor.setCurrentTime(new Date());
		
		CertificateReports reports = executor.execute();
		assertNotNull(reports);
		SimpleCertificateReport simpleReport = reports.getSimpleReport();
		assertNotNull(simpleReport);
		List<String> certIds = simpleReport.getCertificateIds();
		assertTrue(Utils.isCollectionNotEmpty(certIds));
		for (String certId : certIds) {
			Indication indication = simpleReport.getCertificateIndication(certId);
			assertNotNull(indication);
			if (!Indication.PASSED.equals(indication)) {
				SubIndication subIndication = simpleReport.getCertificateSubIndication(certId);
				assertNotNull(subIndication);
			}
		}
	}

}
