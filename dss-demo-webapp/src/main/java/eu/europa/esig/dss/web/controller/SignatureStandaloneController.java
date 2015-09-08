package eu.europa.esig.dss.web.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class SignatureStandaloneController {

	@RequestMapping(value = "/signature-standalone", method = RequestMethod.GET)
	public String getInfo() {
		return "signature-standalone";
	}

	@RequestMapping(value = "/signature-rest", method = RequestMethod.GET)
	public String getRestInfo() {
		return "signature-rest";
	}

}
