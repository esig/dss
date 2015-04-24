package eu.europa.esig.dss.web.service;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;

import javax.annotation.PostConstruct;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Templates;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.URIResolver;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.DefaultConfigurationBuilder;
import org.apache.fop.apps.FOUserAgent;
import org.apache.fop.apps.Fop;
import org.apache.fop.apps.FopFactory;
import org.apache.fop.apps.MimeConstants;
import org.apache.pdfbox.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.validation.report.DetailedReport;
import eu.europa.esig.dss.validation.report.SimpleReport;

@Component
public class FOPService {

	private static final Logger logger = LoggerFactory.getLogger(FOPService.class);

	private FopFactory fopFactory;
	private FOUserAgent foUserAgent;
	private Templates templateSimpleReport;
	private Templates templateDetailedReport;

	@PostConstruct
	public void init() throws Exception {
		DefaultConfigurationBuilder cfgBuilder = new DefaultConfigurationBuilder();
		Configuration cfg = cfgBuilder.build(getClass().getResourceAsStream("/fop/fop.conf.xml"));

		fopFactory = FopFactory.newInstance();
		fopFactory.setUserConfig(cfg);
		fopFactory.setURIResolver(new URIResolver() {
			@Override
			public Source resolve(String href, String base) throws TransformerException {
				InputStream in = getClass().getResourceAsStream("/fop/" + href);
				if (in != null) {
					logger.debug("Found " + href + " in '/fop/'");
					return new StreamSource(in);
				} else {
					return null;
				}
			}
		});

		foUserAgent = fopFactory.newFOUserAgent();
		foUserAgent.setCreator("DSS Webapp");
		foUserAgent.setAccessibility(true);

		TransformerFactory transformerFactory = DSSXMLUtils.getSecureTransformerFactory();

		InputStream simpleIS = FOPService.class.getResourceAsStream("/xslt/simpleReportFop.xslt");
		templateSimpleReport = transformerFactory.newTemplates(new StreamSource(simpleIS));
		IOUtils.closeQuietly(simpleIS);

		InputStream detailedIS = FOPService.class.getResourceAsStream("/xslt/validationReportFop.xslt");
		templateDetailedReport = transformerFactory.newTemplates(new StreamSource(detailedIS));
		IOUtils.closeQuietly(detailedIS);
	}

	public void generateSimpleReport(SimpleReport report, OutputStream os) throws Exception {
		Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, os);
		Result res = new SAXResult(fop.getDefaultHandler());
		Transformer transformer = templateSimpleReport.newTransformer();
		transformer.transform(new StreamSource(new StringReader(report.toString())), res);
	}

	public void generateDetailedReport(DetailedReport report, OutputStream os) throws Exception {
		Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, os);
		Result res = new SAXResult(fop.getDefaultHandler());
		Transformer transformer = templateDetailedReport.newTransformer();
		transformer.transform(new StreamSource(new StringReader(report.toString())), res);
	}

}
