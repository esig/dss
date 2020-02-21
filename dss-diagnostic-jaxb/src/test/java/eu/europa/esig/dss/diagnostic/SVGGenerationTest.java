package eu.europa.esig.dss.diagnostic;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.UUID;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.Result;
import javax.xml.transform.TransformerException;
import javax.xml.transform.stream.StreamResult;

import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;

public class SVGGenerationTest {

	@Test
	public void test() throws JAXBException, XMLStreamException, IOException, SAXException, TransformerException {
		DiagnosticDataFacade newFacade = DiagnosticDataFacade.newFacade();
		XmlDiagnosticData diagnosticData = newFacade.unmarshall(new File("src/test/resources/diag-data.xml"));

		try (FileOutputStream fos = new FileOutputStream("target/" + UUID.randomUUID().toString() + ".svg")) {
			Result result = new StreamResult(fos);
			newFacade.generateSVG(diagnosticData, result);
		}
	}

}
