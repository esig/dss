package eu.europa.esig.dss.web.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.validation.ValidationResourceManager;
import eu.europa.esig.dss.web.service.PolicyJaxbService;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;
import eu.europa.esig.jaxb.policy.TimeUnit;

@Controller
@RequestMapping(value = "/validation-policy")
public class ValidationPolicyController {

	private static final String VALIDATION_POLICY_TILE = "validation-policy";

	@Autowired
	private PolicyJaxbService policyJaxbService;

	@ModelAttribute("supportedDigestAlgos")
	public DigestAlgorithm[] getSupportedDigestAlgos() {
		return DigestAlgorithm.values();
	}

	@ModelAttribute("supportedEncryptionAlgos")
	public EncryptionAlgorithm[] getSupportedEncryptionAlgos() {
		return EncryptionAlgorithm.values();
	}

	@ModelAttribute("timeUnits")
	public TimeUnit[] getTimeUnits() {
		return TimeUnit.values();
	}

	@RequestMapping(method = RequestMethod.GET)
	public String showValidationPolicy(Model model) {

		model.addAttribute("policy", policyJaxbService.unmarshall(ValidationResourceManager.defaultPolicyConstraintsLocation));

		return VALIDATION_POLICY_TILE;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String save(@ModelAttribute("policy") ConstraintsParameters policy, Model model) {

		model.addAttribute("policy", policy);
		model.addAttribute("xmlResult", policyJaxbService.marshall(policy));

		return VALIDATION_POLICY_TILE;
	}
}
