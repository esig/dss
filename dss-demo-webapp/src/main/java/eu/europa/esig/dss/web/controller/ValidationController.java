package eu.europa.esig.dss.web.controller;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.multipart.MultipartFile;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.report.DetailedReport;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.validation.report.SimpleReport;
import eu.europa.esig.dss.web.WebAppUtils;
import eu.europa.esig.dss.web.model.ValidationForm;
import eu.europa.esig.dss.web.service.XSLTService;

@Controller
@SessionAttributes({"simpleReportXml", "detailedReportXml"})
@RequestMapping(value = "/validation")
public class ValidationController {

	private static final Logger logger = LoggerFactory.getLogger(ValidationController.class);

	private static final String VALIDATION_TILE = "validation";
	private static final String VALIDATION_RESULT_TILE = "validation_result";

	private static final String SIMPLE_REPORT_ATTRIBUTE = "simpleReportXml";
	private static final String DETAILED_REPORT_ATTRIBUTE = "detailedReportXml";

	@Autowired
	private CertificateVerifier certificateVerifier;

	@Autowired
	private XSLTService xsltService;

	@RequestMapping(method = RequestMethod.GET)
	public String showValidationForm(Model model) {
		ValidationForm validationForm = new ValidationForm();
		validationForm.setDefaultPolicy(true);
		model.addAttribute("validationForm", validationForm);
		return VALIDATION_TILE;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String validate(@ModelAttribute("validationForm") @Valid ValidationForm validationForm,  BindingResult result, Model model) {
		if (result.hasErrors()) {
			return VALIDATION_TILE;
		}

		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(WebAppUtils.toDSSDocument(validationForm.getSignedFile()));
		documentValidator.setCertificateVerifier(certificateVerifier);

		MultipartFile originalFile = validationForm.getOriginalFile();
		if ((originalFile !=null) && !originalFile.isEmpty()) {
			List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
			detachedContents.add(WebAppUtils.toDSSDocument(originalFile));
			documentValidator.setDetachedContents(detachedContents );
		}

		Reports reports = null;

		MultipartFile policyFile = validationForm.getPolicyFile();
		if (!validationForm.isDefaultPolicy() && (policyFile !=null) && !policyFile.isEmpty()) {
			try {
				reports = documentValidator.validateDocument(policyFile.getInputStream());
			} catch (IOException e) {
				logger.error(e.getMessage(), e);
			}
		} else{
			reports = documentValidator.validateDocument();
		}

		SimpleReport simpleReport = reports.getSimpleReport();
		model.addAttribute(SIMPLE_REPORT_ATTRIBUTE, simpleReport);
		model.addAttribute("simpleReport", xsltService.generateSimpleReport(simpleReport));

		DetailedReport detailedReport = reports.getDetailedReport();
		model.addAttribute(DETAILED_REPORT_ATTRIBUTE, detailedReport);
		model.addAttribute("detailedReport", xsltService.generateDetailedReport(detailedReport));
		model.addAttribute("diagnosticTree", reports.getDiagnosticData().toString());

		return VALIDATION_RESULT_TILE;
	}

	@RequestMapping(value = "/download-simple-report")
	public void downloadSimpleReport(HttpSession session, HttpServletResponse response) {
		try {

			response.setContentType(MimeType.PDF.getMimeTypeString());
			response.setHeader("Content-Disposition", "attachment; filename=DSS-Simple-report.pdf");

			SimpleReport simpleReport = (SimpleReport) session.getAttribute(SIMPLE_REPORT_ATTRIBUTE);

			FopFactory fopFactory = FopFactory.newInstance();
			FOUserAgent foUserAgent = fopFactory.newFOUserAgent();
			foUserAgent.setCreator("DSS Webapp");
			foUserAgent.setCreationDate(new Date());
			foUserAgent.setTitle("Simple validation report");
			foUserAgent.setAccessibility(true);

			InputStream xsltIS = ValidationController.class.getResourceAsStream("/xslt/simpleReportFop.xslt");
			Source xslt = new StreamSource(xsltIS);

			Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, response.getOutputStream());

			TransformerFactory transformerFactory = DSSXMLUtils.getSecureTransformerFactory();
			Transformer transformer = transformerFactory.newTransformer(xslt);

			Result res = new SAXResult(fop.getDefaultHandler());
			transformer.transform(new StreamSource(new StringReader(simpleReport.toString())), res);

		} catch (Exception e) {
			logger.error("An error occured while generating pdf for simple report : " + e.getMessage(), e);
		}

	}

}
