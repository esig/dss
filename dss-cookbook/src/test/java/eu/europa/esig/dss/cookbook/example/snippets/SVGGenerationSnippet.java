package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;

import javax.xml.transform.Result;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.FileOutputStream;

public class SVGGenerationSnippet {

    @SuppressWarnings("unused")
    public void demo() throws Exception {

        // tag::demo[]

        // Initialize DiagnosticData to create an SVG image from
        File diagnosticDataXmlFile = new File("src/test/resources/diag-data.xml");

        // Initialize the DiagnosticData facade in order to unmarshall the XML Diagnostic Data
        DiagnosticDataFacade newFacade = DiagnosticDataFacade.newFacade();

        // Unmarshall the DiagnosticData
        XmlDiagnosticData diagnosticData = newFacade.unmarshall(diagnosticDataXmlFile);

        // Generate and store the SVG image
        try (FileOutputStream fos = new FileOutputStream("target/diag-data.svg")) {
            Result result = new StreamResult(fos);
            newFacade.generateSVG(diagnosticData, result);
        }

        // end::demo[]

    }

}
