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
package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicValidation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class EvidenceRecordValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void erWithNotIdentifiedDigestAlgoTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/er-validation/er-valid.xml"));
        assertNotNull(diagnosticData);

        XmlEvidenceRecord evidenceRecord = diagnosticData.getEvidenceRecords().get(0);
        for (XmlDigestMatcher digestMatcher : evidenceRecord.getDigestMatchers()) {
            digestMatcher.setDigestMethod(null);
            digestMatcher.setDigestValue(null);
            digestMatcher.setDataIntact(false);
        }

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        checkReports(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.FAILED, simpleReport.getIndication(simpleReport.getFirstEvidenceRecordId()));
        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstEvidenceRecordId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord xmlEvidenceRecord =
                detailedReport.getXmlEvidenceRecordById(detailedReport.getFirstEvidenceRecordId());
        assertNotNull(xmlEvidenceRecord);

        XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
        assertNotNull(validationProcessEvidenceRecord);
        assertEquals(Indication.FAILED, validationProcessEvidenceRecord.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, validationProcessEvidenceRecord.getConclusion().getSubIndication());

        XmlCryptographicValidation cryptographicValidation = validationProcessEvidenceRecord.getCryptographicValidation();
        assertNotNull(cryptographicValidation);
        assertNotNull(cryptographicValidation.getAlgorithm());
        assertEquals("UNIDENTIFIED", cryptographicValidation.getAlgorithm().getName());
        assertEquals("urn:etsi:019102:algorithm:unidentified", cryptographicValidation.getAlgorithm().getUri());
        assertEquals(diagnosticData.getUsedTimestamps().get(0).getProductionTime(), cryptographicValidation.getValidationTime());
        assertEquals(evidenceRecord.getId(), cryptographicValidation.getConcernedMaterial());
    }

}
