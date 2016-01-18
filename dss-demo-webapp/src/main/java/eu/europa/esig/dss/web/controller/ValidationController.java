package eu.europa.esig.dss.web.controller;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.multipart.MultipartFile;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.EN319102.report.Reports;
import eu.europa.esig.dss.EN319102.wrappers.DiagnosticData;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.web.WebAppUtils;
import eu.europa.esig.dss.web.model.ValidationForm;
import eu.europa.esig.dss.web.service.FOPService;
import eu.europa.esig.dss.web.service.XSLTService;

@Controller
@SessionAttributes({ "simpleReportXml", "detailedReportXml", "reportsList" })
@RequestMapping(value = "/validation")
public class ValidationController {

	private static final Logger logger = LoggerFactory.getLogger(ValidationController.class);

	private static final String VALIDATION_TILE = "validation";
	private static final String VALIDATION_RESULT_TILE = "validation_result";

	private static final String SIMPLE_REPORT_ATTRIBUTE = "simpleReportXml";
	private static final String DETAILED_REPORT_ATTRIBUTE = "detailedReportXml";
	private static final String REPORTS_LIST = "reportsList";

	@Autowired
	private CertificateVerifier certificateVerifier;

	@Autowired
	private XSLTService xsltService;

	@Autowired
	private FOPService fopService;

	@RequestMapping(method = RequestMethod.GET)
	public String showValidationForm(Model model) {
		ValidationForm validationForm = new ValidationForm();
		validationForm.setDefaultPolicy(true);
		model.addAttribute("validationForm", validationForm);
		return VALIDATION_TILE;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String validate(@ModelAttribute("validationForm") @Valid ValidationForm validationForm, BindingResult result, Model model) {
		if (result.hasErrors()) {
			return VALIDATION_TILE;
		}

		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(WebAppUtils.toDSSDocument(validationForm.getSignedFile()));
		documentValidator.setCertificateVerifier(certificateVerifier);

		MultipartFile originalFile = validationForm.getOriginalFile();
		if ((originalFile != null) && !originalFile.isEmpty()) {
			List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
			detachedContents.add(WebAppUtils.toDSSDocument(originalFile));
			documentValidator.setDetachedContents(detachedContents);
		}

		Reports reports = null;

		MultipartFile policyFile = validationForm.getPolicyFile();
		if (!validationForm.isDefaultPolicy() && (policyFile != null) && !policyFile.isEmpty()) {
			try {
				reports = documentValidator.validateDocument(policyFile.getInputStream());
			} catch (IOException e) {
				logger.error(e.getMessage(), e);
			}
		} else {
			reports = documentValidator.validateDocument();
		}

		String xmlSimpleReport = reports.getXmlSimpleReport();
		model.addAttribute(SIMPLE_REPORT_ATTRIBUTE, xmlSimpleReport);
		model.addAttribute("simpleReport", xsltService.generateSimpleReport(xmlSimpleReport));

		String xmlDetailedReport = reports.getXmlDetailedReport();
		model.addAttribute(DETAILED_REPORT_ATTRIBUTE, xmlDetailedReport);
		model.addAttribute("detailedReport", xsltService.generateDetailedReport(xmlDetailedReport));

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		model.addAttribute("diagnosticTree", reports.getXmlDiagnosticData());

		List<String> reportsNameList = new ArrayList<String>();
		List<Reports> reportsList = new ArrayList<Reports>();
		while (reports != null) {
			reportsNameList.add(diagnosticData.getDocumentName());
			reportsList.add(reports);
			reports = reports.getNextReports();
		}
		model.addAttribute(REPORTS_LIST, reportsList);
		model.addAttribute("reports", reportsNameList);

		return VALIDATION_RESULT_TILE;
	}

	@SuppressWarnings("unchecked")
	@RequestMapping(value = "/report", method = RequestMethod.GET)
	public String getReports(@RequestParam("name") String reportFileName, HttpSession session, Model model) {
		Reports reports = null;
		List<Reports> reportsList = (List<Reports>) session.getAttribute(REPORTS_LIST);
		List<String> reportsNameList = new ArrayList<String>();
		for (Reports report : reportsList) {
			DiagnosticData diagnosticData = report.getDiagnosticData();
			String documentName = diagnosticData.getDocumentName();
			String name = documentName.substring(documentName.lastIndexOf("/") + 1);
			if (name.equals(reportFileName)) {
				reportsNameList.add(documentName);
				reports = report;
			}
		}

		String xmlSimpleReport = reports.getXmlSimpleReport();
		model.addAttribute(SIMPLE_REPORT_ATTRIBUTE, xmlSimpleReport);
		model.addAttribute("simpleReport", xsltService.generateSimpleReport(xmlSimpleReport));

		String xmlDetailedReport = reports.getXmlDetailedReport();
		model.addAttribute(DETAILED_REPORT_ATTRIBUTE, xmlDetailedReport);
		model.addAttribute("detailedReport", xsltService.generateDetailedReport(xmlDetailedReport));

		model.addAttribute("diagnosticTree", reports.getXmlDiagnosticData());

		for (Reports report : reportsList) {
			if (report != reports) {
				DiagnosticData diagnosticData = report.getDiagnosticData();
				reportsNameList.add(diagnosticData.getDocumentName());
			}
		}
		model.addAttribute("reports", reportsNameList);

		return VALIDATION_RESULT_TILE;
	}

	@RequestMapping(value = "/download-simple-report")
	public void downloadSimpleReport(HttpSession session, HttpServletResponse response) {
		try {
			String simpleReport = (String) session.getAttribute(SIMPLE_REPORT_ATTRIBUTE);

			response.setContentType(MimeType.PDF.getMimeTypeString());
			response.setHeader("Content-Disposition", "attachment; filename=DSS-Simple-report.pdf");

			fopService.generateSimpleReport(simpleReport, response.getOutputStream());
		} catch (Exception e) {
			logger.error("An error occured while generating pdf for simple report : " + e.getMessage(), e);
		}
	}

	@RequestMapping(value = "/download-detailed-report")
	public void downloadDetailedReport(HttpSession session, HttpServletResponse response) {
		try {
			String detailedReport = (String) session.getAttribute(DETAILED_REPORT_ATTRIBUTE);

			response.setContentType(MimeType.PDF.getMimeTypeString());
			response.setHeader("Content-Disposition", "attachment; filename=DSS-Detailed-report.pdf");

			fopService.generateDetailedReport(detailedReport, response.getOutputStream());
		} catch (Exception e) {
			logger.error("An error occured while generating pdf for detailed report : " + e.getMessage(), e);
		}
	}

}