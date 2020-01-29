package eu.europa.esig.dss.cookbook.example.snippets;

import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;

import javax.xml.transform.Transformer;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReportXmlDefiner;
import eu.europa.esig.dss.simplereport.SimpleReportFacade;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;

public class StylesheetSnippet {
	
	@SuppressWarnings("unused")
	public void demo() {
		
		XmlSimpleReport xmlSimpleReport = new XmlSimpleReport();
		try {
			// tag::demo[]
			String bootstrap3Report = SimpleReportFacade.newFacade().generateHtmlBootstrap3Report(xmlSimpleReport);
			// end::demo[]
		} catch (Exception e) {
			// catch the exception
		}
		
		
		String simpleReport = null;
		// tag::custom[]
		try (Writer writer = new StringWriter()) {
			Transformer transformer = SimpleCertificateReportXmlDefiner.getHtmlBootstrap3Templates().newTransformer();
			// specify custom parameters if needed
			transformer.transform(new StreamSource(new StringReader(simpleReport)), new StreamResult(writer));
			String bootstrap3Report = writer.toString();
		} 
		// end::custom[]
		catch (Exception e) {
			// catch the exception
		}
	}

}
