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
package eu.europa.esig.dss.validation.timestamp;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.SimpleReportFacade;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import jakarta.xml.bind.JAXBException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TimestampDocumentValidatorPoliciesTest {

    static Stream<Arguments> data() {
        File folderPolicy = new File("src/test/resources/diag-data/policy");
        File cryptoSuitesFolder = new File("src/test/resources/diag-data/crypto-suite");
        Collection<Arguments> dataToRun = new ArrayList<>();

        for (File policyFile : folderPolicy.listFiles()) {
            if (policyFile.isFile()) {
                for (File cryptoSuiteFile : cryptoSuitesFolder.listFiles()) {
                    if (cryptoSuiteFile.isFile()) {
                        dataToRun.add(Arguments.of(policyFile, cryptoSuiteFile));
                    }
                }
            }
        }

        return dataToRun.stream();
    }

    @ParameterizedTest(name = "Execution {index} : {0} + {1}")
    @MethodSource("data")
    void test(File policyFile, File cryptoSuiteFile) throws JAXBException, IOException, SAXException {
        DSSDocument timestamp = new FileDocument("src/test/resources/d-trust.tsr");
        DSSDocument timestampedContent = new InMemoryDocument("Test123".getBytes());

        DocumentValidator validator = SignedDocumentValidator.fromDocument(timestamp);
        validator.setDetachedContents(Collections.singletonList(timestampedContent));
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        Reports reports = validator.validateDocument(policyFile, cryptoSuiteFile);
        validate(reports);
    }

    private void validate(Reports reports) throws JAXBException, IOException, SAXException {
        assertNotNull(reports);
        assertNotNull(reports.getDiagnosticDataJaxb());
        assertNotNull(reports.getXmlDiagnosticData());
        assertNotNull(reports.getDetailedReportJaxb());
        assertNotNull(reports.getXmlDetailedReport());
        assertNotNull(reports.getSimpleReportJaxb());
        assertNotNull(reports.getXmlSimpleReport());

        SimpleReportFacade simpleReportFacade = SimpleReportFacade.newFacade();
        String marshalled = simpleReportFacade.marshall(reports.getSimpleReportJaxb(), true);
        assertNotNull(marshalled);

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(1, timestampList.size());
        TimestampWrapper timestampWrapper = timestampList.get(0);

        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());

        assertEquals(1, timestampWrapper.getTimestampScopes().size());
        assertEquals(1, timestampWrapper.getTimestampedSignedData().size());

        SimpleReport simpleReport = reports.getSimpleReport();
        List<String> timestampIdList = simpleReport.getTimestampIdList();
        assertEquals(1, timestampIdList.size());
        assertNotNull(simpleReport.getFirstTimestampId());
        assertNotNull(simpleReport.getIndication(simpleReport.getFirstTimestampId()));
    }

    private CertificateVerifier getOfflineCertificateVerifier() {
        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setAIASource(null);
        return cv;
    }

}
