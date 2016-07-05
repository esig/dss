package eu.europa.esig.dss.web.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.utils.Utils;

@Controller
@RequestMapping(value = "/tsl-info")
public class TrustedListController {

	@Autowired
	private TSLRepository tslRepository;

	@RequestMapping(method = RequestMethod.GET)
	public String getSummary(final Model model) {
		model.addAttribute("summary", tslRepository.getSummary());
		return "tsl-info";
	}

	@RequestMapping(value = "/{country:[a-z][a-z]}", method = RequestMethod.GET)
	public String getByCountry(@PathVariable String country, Model model) {
		String countryUppercase = Utils.upperCase(country);
		model.addAttribute("country", countryUppercase);
		model.addAttribute("countries", tslRepository.getAllMapTSLValidationModels().keySet());
		model.addAttribute("model", tslRepository.getByCountry(countryUppercase));
		return "tsl-info-country";
	}

}
