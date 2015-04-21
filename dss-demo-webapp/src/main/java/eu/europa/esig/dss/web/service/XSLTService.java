package eu.europa.esig.dss.web.service;

import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.validation.report.DetailedReport;
import eu.europa.esig.dss.validation.report.SimpleReport;

@Component
public class XSLTService {

	private static final Logger logger = LoggerFactory.getLogger(XSLTService.class);

	public String generateSimpleReport(SimpleReport simpleReport) {
		Writer writer = new StringWriter();
		try {
			TransformerFactory transformerFactory = DSSXMLUtils.getSecureTransformerFactory();
			Transformer transformer = transformerFactory.newTransformer(new StreamSource(XSLTService.class.getResourceAsStream("/xslt/simpleReport.xslt")));
			transformer.transform(new StreamSource(new StringReader(simpleReport.toString())), new StreamResult(writer));
		} catch (Exception e) {
			logger.error("Error while generating simple report : " + e.getMessage(), e);
		}
		return writer.toString();
	}

	public String generateDetailedReport(DetailedReport detailedReport) {
		// TODO Auto-generated method stub
		return null;
	}

}