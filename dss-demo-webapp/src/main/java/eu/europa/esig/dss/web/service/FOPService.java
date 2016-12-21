package eu.europa.esig.dss.web.service;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;

import javax.annotation.PostConstruct;
import javax.xml.transform.Result;
import javax.xml.transform.Templates;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.fop.apps.FOUserAgent;
import org.apache.fop.apps.Fop;
import org.apache.fop.apps.FopFactory;
import org.apache.fop.apps.FopFactoryBuilder;
import org.apache.fop.apps.MimeConstants;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;

import eu.europa.esig.dss.DSSXmlErrorListener;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.utils.Utils;

@Component
public class FOPService {

	private FopFactory fopFactory;
	private FOUserAgent foUserAgent;
	private Templates templateSimpleReport;
	private Templates templateDetailedReport;

	@PostConstruct
	public void init() throws Exception {

		FopFactoryBuilder builder = new FopFactoryBuilder(new File(".").toURI());
		builder.setAccessibility(true);

		fopFactory = builder.build();

		foUserAgent = fopFactory.newFOUserAgent();
		foUserAgent.setCreator("DSS Webapp");
		foUserAgent.setAccessibility(true);

		TransformerFactory transformerFactory = DomUtils.getSecureTransformerFactory();

		InputStream simpleIS = FOPService.class.getResourceAsStream("/xslt/pdf/simple-report.xslt");
		templateSimpleReport = transformerFactory.newTemplates(new StreamSource(simpleIS));
		Utils.closeQuietly(simpleIS);

		InputStream detailedIS = FOPService.class.getResourceAsStream("/xslt/pdf/detailed-report.xslt");
		templateDetailedReport = transformerFactory.newTemplates(new StreamSource(detailedIS));
		Utils.closeQuietly(detailedIS);
	}

	public void generateSimpleReport(String simpleReport, OutputStream os) throws Exception {
		Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, os);
		Result res = new SAXResult(fop.getDefaultHandler());
		Transformer transformer = templateSimpleReport.newTransformer();
		transformer.setErrorListener(new DSSXmlErrorListener());
		transformer.transform(new StreamSource(new StringReader(simpleReport)), res);
	}

	public void generateSimpleReport(Document dom, OutputStream os) throws Exception {
		Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, os);
		Result res = new SAXResult(fop.getDefaultHandler());
		Transformer transformer = templateSimpleReport.newTransformer();
		transformer.setErrorListener(new DSSXmlErrorListener());
		transformer.transform(new DOMSource(dom), res);
	}

	public void generateDetailedReport(String detailedReport, OutputStream os) throws Exception {
		Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, os);
		Result res = new SAXResult(fop.getDefaultHandler());
		Transformer transformer = templateDetailedReport.newTransformer();
		transformer.setErrorListener(new DSSXmlErrorListener());
		transformer.transform(new StreamSource(new StringReader(detailedReport)), res);
	}

}
