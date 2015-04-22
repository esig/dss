package eu.europa.esig.dss.web.service;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;

import javax.annotation.PostConstruct;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.fop.apps.FOUserAgent;
import org.apache.fop.apps.Fop;
import org.apache.fop.apps.FopFactory;
import org.apache.fop.apps.MimeConstants;
import org.springframework.stereotype.Component;

import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.validation.report.DetailedReport;
import eu.europa.esig.dss.validation.report.SimpleReport;

@Component
public class FOPService {
	
	private FopFactory fopFactory;
	private FOUserAgent foUserAgent;
	private Source xsltSimpleReport;
	private Source xsltDetailedReport;
	
	@PostConstruct
	public void init(){
		fopFactory = FopFactory.newInstance();

		foUserAgent = fopFactory.newFOUserAgent();
		foUserAgent.setCreator("DSS Webapp");
		foUserAgent.setAccessibility(true);

		InputStream simpleIS = FOPService.class.getResourceAsStream("/xslt/simpleReportFop.xslt");
		xsltSimpleReport = new StreamSource(simpleIS);

		InputStream detailedIS = FOPService.class.getResourceAsStream("/xslt/validationReportFop.xslt");
		xsltDetailedReport = new StreamSource(detailedIS);
	}
	
	public void generateSimpleReport(SimpleReport report, OutputStream os) throws Exception {
		Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, os);
		
		TransformerFactory transformerFactory = DSSXMLUtils.getSecureTransformerFactory();
		Transformer transformer = transformerFactory.newTransformer(xsltSimpleReport);

		Result res = new SAXResult(fop.getDefaultHandler());
		transformer.transform(new StreamSource(new StringReader(report.toString())), res);
	}

	public void generateDetailedReport(DetailedReport report, OutputStream os) throws Exception {
		Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, os);
		
		TransformerFactory transformerFactory = DSSXMLUtils.getSecureTransformerFactory();
		Transformer transformer = transformerFactory.newTransformer(xsltDetailedReport);

		Result res = new SAXResult(fop.getDefaultHandler());
		transformer.transform(new StreamSource(new StringReader(report.toString())), res);
	}

}
