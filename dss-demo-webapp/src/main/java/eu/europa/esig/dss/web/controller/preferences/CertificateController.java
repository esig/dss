package eu.europa.esig.dss.web.controller.preferences;

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
import org.springframework.web.bind.annotation.SessionAttributes;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.web.model.CertificateForm;
import eu.europa.esig.dss.web.service.KeystoreService;
import eu.europa.esig.dss.x509.CertificateToken;

@Controller
@SessionAttributes(value = "certificateForm")
@RequestMapping(value = "/admin/certificates")
public class CertificateController {

	private static final Logger logger = LoggerFactory.getLogger(CertificateController.class);

	private static final String CERTIFICATE_TILE = "admin-select-certificate";

	@Autowired
	private KeystoreService keystoreService;

	@RequestMapping(method = RequestMethod.GET)
	public String showCertificates(Model model, HttpServletRequest request) {
		CertificateForm certificateForm = new CertificateForm();
		model.addAttribute("certificateForm", certificateForm);
		model.addAttribute("keystoreCertificates", keystoreService.getCertificatesDTOFromKeyStore());
		return CERTIFICATE_TILE;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String uploadCertificate(Model model, HttpServletRequest request, HttpServletResponse response,
			@ModelAttribute("certificateForm") @Valid CertificateForm certificateForm, BindingResult result) {

		if (result.hasErrors()) {
			model.addAttribute("keystoreCertificates", keystoreService.getCertificatesDTOFromKeyStore());
			return CERTIFICATE_TILE;
		}

		try {
			CertificateToken certificateToken = DSSUtils.loadCertificate(certificateForm.getCertificateFile().getBytes());
			model.addAttribute("certificateDTO", keystoreService.getCertificateDTO(certificateToken));
			if (certificateForm.isAddToKeystore()) {
				keystoreService.addCertificateToKeyStore(certificateToken);
			}
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}

		model.addAttribute("keystoreCertificates", keystoreService.getCertificatesDTOFromKeyStore());
		return CERTIFICATE_TILE;
	}

	@RequestMapping(method = RequestMethod.POST, params = "delete")
	public String deleteCertificate(Model model, HttpServletRequest request, HttpServletResponse response) {
		keystoreService.deleteCertificateFromKeyStore(request.getParameter("dssId"));
		model.addAttribute("keystoreCertificates", keystoreService.getCertificatesDTOFromKeyStore());
		model.addAttribute("certificateForm", new CertificateForm());
		return CERTIFICATE_TILE;
	}

}