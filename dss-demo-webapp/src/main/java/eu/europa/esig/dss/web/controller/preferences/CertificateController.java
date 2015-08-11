package eu.europa.esig.dss.web.controller.preferences;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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

import eu.europa.esig.dss.web.model.CertificateDTO;
import eu.europa.esig.dss.web.model.CertificateForm;
import eu.europa.esig.dss.web.service.KeystoreService;

@Controller
@RequestMapping(value = "/admin/certificates")
public class CertificateController {

	private static final Logger logger = LoggerFactory.getLogger(CertificateController.class);

	private static final String CERTIFICATE_TILE = "admin-select-certificate";

	@Autowired
	private KeystoreService keystoreService;

	@ModelAttribute("keystoreCertificates")
	public List<CertificateDTO> getKeystoreCertificates() {
		return keystoreService.loadCertificatesFromKeryStore();
	}

	@RequestMapping(method = RequestMethod.GET)
	public String showCertificates(Model model, HttpServletRequest request) {
		CertificateForm certificateForm = new CertificateForm();
		model.addAttribute("certificateForm", certificateForm);
		return CERTIFICATE_TILE;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String uploadCertificate(Model model, HttpServletRequest request, HttpServletResponse response,
			@ModelAttribute("certificateForm") @Valid CertificateForm certificateForm, BindingResult result) {

		if (result.hasErrors()) {
			return CERTIFICATE_TILE;
		}

		try {
			CertificateDTO certificateDTO = keystoreService.getCertificateDTO(certificateForm.getCertificateFile().getBytes());
			model.addAttribute("certificateDTO", certificateDTO);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}

		return CERTIFICATE_TILE;
	}

}