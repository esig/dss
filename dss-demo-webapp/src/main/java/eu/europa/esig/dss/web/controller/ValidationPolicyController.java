package eu.europa.esig.dss.web.controller;

import java.io.InputStream;

import javax.xml.transform.stream.StreamSource;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.oxm.Unmarshaller;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import eu.europa.esig.dss.validation.ValidationResourceManager;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

@Controller
@RequestMapping(value = "/validation-policy")
public class ValidationPolicyController {

	private static final Logger logger = LoggerFactory.getLogger(ValidationPolicyController.class);

	private static final String VALIDATION_POLICY_TILE = "validation-policy";

	@Autowired
	private Unmarshaller policyMarshaller;

	@RequestMapping(method = RequestMethod.GET)
	public String showValidationPolicy(Model model) {

		InputStream is = null;
		ConstraintsParameters policy = null;
		try {
			is = ValidationPolicyController.class.getResourceAsStream(ValidationResourceManager.defaultPolicyConstraintsLocation);
			policy = (ConstraintsParameters) policyMarshaller.unmarshal(new StreamSource(is));
		} catch (Exception e) {
			logger.error("Unable to parse '" + ValidationResourceManager.defaultPolicyConstraintsLocation + "' : " + e.getMessage(), e);
		} finally {
			IOUtils.closeQuietly(is);
		}

		model.addAttribute("policy", policy);

		return VALIDATION_POLICY_TILE;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String save(@ModelAttribute("policy") ConstraintsParameters policy, Model model) {

		model.addAttribute("policy", policy);

		return VALIDATION_POLICY_TILE;
	}
}
