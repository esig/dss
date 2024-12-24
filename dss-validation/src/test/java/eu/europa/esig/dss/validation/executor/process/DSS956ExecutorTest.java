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
package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS956ExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void testDSS956AllValidationLevels() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/passed_revoked_with_timestamp.xml"));
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

}
