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
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;

import javax.xml.transform.Result;
import java.io.File;
import java.io.FileOutputStream;

public class SVGGenerationSnippet {

    @SuppressWarnings("unused")
    public void demo() throws Exception {

        // tag::demo[]
        // import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
        // import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
        // import javax.xml.transform.Result;
        // import java.io.File;
        // import java.io.FileOutputStream;

        // Initialize DiagnosticData to create an SVG image from
        File diagnosticDataXmlFile = new java.io.File("src/test/resources/diag-data.xml");

        // Initialize the DiagnosticData facade in order to unmarshall the XML Diagnostic Data
        DiagnosticDataFacade newFacade = eu.europa.esig.dss.diagnostic.DiagnosticDataFacade.newFacade();

        // Unmarshall the DiagnosticData
        XmlDiagnosticData diagnosticData = newFacade.unmarshall(diagnosticDataXmlFile);

        // Generate and store the SVG image
        try (FileOutputStream fos = new java.io.FileOutputStream("target/diag-data.svg")) {
            Result result = new javax.xml.transform.stream.StreamResult(fos);
            newFacade.generateSVG(diagnosticData, result);
        }

        // end::demo[]

    }

}
