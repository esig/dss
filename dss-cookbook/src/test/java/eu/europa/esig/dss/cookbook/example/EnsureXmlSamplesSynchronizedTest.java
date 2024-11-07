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
package eu.europa.esig.dss.cookbook.example;

import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.simplereport.SimpleReportFacade;
import eu.europa.esig.validationreport.ValidationReportFacade;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class EnsureXmlSamplesSynchronizedTest {

    @Test
    void constraint() throws Exception {
        assertNotNull(ValidationPolicyFacade.newFacade().getValidationPolicy(new File("src/main/asciidoc/_samples/constraint.xml")));
    }

    @Test
    void simpleReport() throws Exception {
        assertNotNull(SimpleReportFacade.newFacade().unmarshall(new File("src/main/asciidoc/_samples/simple-report-example.xml")));
    }

    @Test
    void detailedReport() throws Exception {
        assertNotNull(DetailedReportFacade.newFacade().unmarshall(new File("src/main/asciidoc/_samples/detailed-report-example.xml")));
    }

    @Test
    void detailedReportTimestamp() throws Exception {
        assertNotNull(DetailedReportFacade.newFacade().unmarshall(new File("src/main/asciidoc/_samples/timestamp-detailed-report-example.xml")));
    }

    @Test
    void diagnosticData() throws Exception {
        assertNotNull(DiagnosticDataFacade.newFacade().unmarshall(new File("src/main/asciidoc/_samples/diagnostic-data-example.xml")));
    }

    @Test
    void etsiVR() throws Exception {
        assertNotNull(ValidationReportFacade.newFacade().unmarshall(new File("src/main/asciidoc/_samples/etsi-validation-report-example.xml")));
    }

}
