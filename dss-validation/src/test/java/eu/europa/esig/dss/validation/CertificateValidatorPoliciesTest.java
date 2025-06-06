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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReportFacade;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import jakarta.xml.bind.JAXBException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.xml.sax.SAXException;

import javax.xml.stream.XMLStreamException;
import javax.xml.transform.TransformerException;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class CertificateValidatorPoliciesTest {

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
    void test(File policyFile, File cryptoSuiteFile) throws JAXBException, IOException, SAXException, TransformerException, XMLStreamException {
        CertificateValidator cv = CertificateValidator.fromCertificate(DSSUtils.loadCertificate(new File("src/test/resources/certificates/CZ.cer")));
        cv.setCertificateVerifier(new CommonCertificateVerifier());

        CertificateReports reports = cv.validate(policyFile, cryptoSuiteFile);
        validateReports(reports);
    }

    private void validateReports(CertificateReports reports) throws JAXBException, IOException, SAXException, TransformerException, XMLStreamException {
        assertNotNull(reports);
        assertNotNull(reports.getDiagnosticDataJaxb());
        assertNotNull(reports.getXmlDiagnosticData());
        assertNotNull(reports.getDetailedReportJaxb());
        assertNotNull(reports.getXmlDetailedReport());
        assertNotNull(reports.getSimpleReportJaxb());
        assertNotNull(reports.getXmlSimpleReport());

        DiagnosticDataFacade diagnosticDataFacade = DiagnosticDataFacade.newFacade();
        String marshalled = diagnosticDataFacade.marshall(reports.getDiagnosticDataJaxb(), true);
        assertNotNull(marshalled);
        XmlDiagnosticData unmarshalled = diagnosticDataFacade.unmarshall(marshalled);
        assertNotNull(unmarshalled);

        SimpleCertificateReportFacade simpleCertificateReportFacade = SimpleCertificateReportFacade.newFacade();
        String marshalledSimpleReport = simpleCertificateReportFacade.marshall(reports.getSimpleReportJaxb(), true);
        assertNotNull(marshalledSimpleReport);
        XmlSimpleCertificateReport unmarshalledSimpleReport = simpleCertificateReportFacade.unmarshall(marshalledSimpleReport);
        assertNotNull(unmarshalledSimpleReport);
        assertNotNull(simpleCertificateReportFacade.generateHtmlReport(marshalledSimpleReport));
        assertNotNull(simpleCertificateReportFacade.generateHtmlReport(reports.getSimpleReportJaxb()));

        DetailedReportFacade detailedReportFacade = DetailedReportFacade.newFacade();
        String marshalledDetailedReport = detailedReportFacade.marshall(reports.getDetailedReportJaxb(), true);
        assertNotNull(marshalledDetailedReport);
        XmlDetailedReport unmarshalledDetailedReport = detailedReportFacade.unmarshall(marshalledDetailedReport);
        assertNotNull(unmarshalledDetailedReport);
        assertNotNull(detailedReportFacade.generateHtmlReport(marshalledDetailedReport));
        assertNotNull(detailedReportFacade.generateHtmlReport(reports.getDetailedReportJaxb()));
    }

}
