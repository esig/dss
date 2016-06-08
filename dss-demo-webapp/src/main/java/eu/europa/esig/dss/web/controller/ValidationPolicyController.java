package eu.europa.esig.dss.web.controller;

import java.io.ByteArrayInputStream;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.propertyeditors.StringTrimmerEditor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.tsl.KeyUsageBit;
import eu.europa.esig.dss.validation.ValidationResourceManager;
import eu.europa.esig.dss.web.service.PolicyJaxbService;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;
import eu.europa.esig.jaxb.policy.TimeUnit;

@Controller
@RequestMapping(value = "/validation-policy")
public class ValidationPolicyController {

	private static final Logger logger = LoggerFactory.getLogger(ValidationPolicyController.class);

	private static final String VALIDATION_POLICY_TILE = "validation-policy";

	@Autowired
	private PolicyJaxbService policyJaxbService;
	
	@InitBinder
	public void initBinder(WebDataBinder binder) {
		binder.registerCustomEditor(String.class, new StringTrimmerEditor(true));
	}

	@ModelAttribute("supportedDigestAlgos")
	public DigestAlgorithm[] getSupportedDigestAlgos() {
		return DigestAlgorithm.values();
	}

	@ModelAttribute("supportedEncryptionAlgos")
	public EncryptionAlgorithm[] getSupportedEncryptionAlgos() {
		return EncryptionAlgorithm.values();
	}

	@ModelAttribute("supportedPolicies")
	public String[] getSupportedPolicies() {
		return new String[] {
				"NO_POLICY", "ANY_POLICY", "IMPLICIT_POLICY"
		};
	}

	@ModelAttribute("timeUnits")
	public TimeUnit[] getTimeUnits() {
		return TimeUnit.values();
	}

	@ModelAttribute("keyUsages")
	public KeyUsageBit[] getKeyUsages() {
		return KeyUsageBit.values();
	}

	@RequestMapping(method = RequestMethod.GET)
	public String showValidationPolicy(Model model) {

		model.addAttribute("policy", policyJaxbService.unmarshall(ValidationResourceManager.defaultPolicyConstraintsLocation));

		return VALIDATION_POLICY_TILE;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String save(@ModelAttribute("policy") ConstraintsParameters policy, Model model, HttpServletResponse response) {

		model.addAttribute("policy", policy);
		String xmlResult = policyJaxbService.marshall(policy);
		model.addAttribute("xmlResult", xmlResult);

		try {
			response.setContentType("application/force-download");
			response.setHeader("Content-Transfer-Encoding", "binary");
			response.setHeader("Content-Disposition", "attachment; filename=constraints.xml");
			IOUtils.copy(new ByteArrayInputStream(xmlResult.getBytes()), response.getOutputStream());

			return null;
		} catch (Exception e) {
			logger.error("An error occured while pushing file in response : " + e.getMessage(), e);
		}

		return VALIDATION_POLICY_TILE;
	}
}
