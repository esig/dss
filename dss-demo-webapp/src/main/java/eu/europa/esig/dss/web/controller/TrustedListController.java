package eu.europa.esig.dss.web.controller;

import java.util.Map;
import java.util.TreeMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.tsl.service.TSLRepository;

@Controller
public class TrustedListController {

	@Autowired
	private TSLRepository tslRepository;

	@RequestMapping(value = "/tsl-info", method = RequestMethod.GET)
	public String showSignature(final Model model) {
		Map<String, TSLValidationModel> mapTSLValidationModels = tslRepository.getAllMapTSLValidationModels();
		model.addAttribute("mapValidations", new TreeMap<String, TSLValidationModel>(mapTSLValidationModels));
		return "tsl-info";
	}

}
