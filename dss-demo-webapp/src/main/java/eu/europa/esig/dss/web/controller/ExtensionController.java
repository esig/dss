package eu.europa.esig.dss.web.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.web.editor.EnumPropertyEditor;
import eu.europa.esig.dss.web.model.ExtensionForm;
import eu.europa.esig.dss.web.service.SigningService;

@Controller
@RequestMapping(value = "/extension")
public class ExtensionController {

	private static final Logger logger = LoggerFactory.getLogger(ExtensionController.class);

	private static final String EXTENSION_TILE = "extension";

	@Autowired
	private SigningService signingService;

	@InitBinder
	public void initBinder(WebDataBinder binder) {
		binder.registerCustomEditor(ASiCContainerType.class, new EnumPropertyEditor(ASiCContainerType.class));
		binder.registerCustomEditor(SignatureForm.class, new EnumPropertyEditor(SignatureForm.class));
		binder.registerCustomEditor(SignaturePackaging.class, new EnumPropertyEditor(SignaturePackaging.class));
		binder.registerCustomEditor(SignatureLevel.class, new EnumPropertyEditor(SignatureLevel.class));
	}

	@RequestMapping(method = RequestMethod.GET)
	public String showExtension(Model model) {
		model.addAttribute("extensionForm", new ExtensionForm());
		return EXTENSION_TILE;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String extend(HttpServletRequest request, HttpServletResponse response, @ModelAttribute("extensionForm") @Valid ExtensionForm extensionForm,
			BindingResult result) {
		if (result.hasErrors()) {
			return EXTENSION_TILE;
		}

		DSSDocument extendedDocument = signingService.extend(extensionForm);

		response.setContentType(extendedDocument.getMimeType().getMimeTypeString());
		response.setHeader("Content-Disposition", "attachment; filename=\"" + extendedDocument.getName() + "\"");
		try {
			Utils.copy(extendedDocument.openStream(), response.getOutputStream());
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}

		return null;
	}

	@ModelAttribute("asicContainerTypes")
	public ASiCContainerType[] getASiCContainerTypes() {
		return ASiCContainerType.values();
	}

	@ModelAttribute("signatureForms")
	public SignatureForm[] getSignatureForms() {
		return SignatureForm.values();
	}

	@ModelAttribute("signaturePackagings")
	public SignaturePackaging[] getSignaturePackagings() {
		return SignaturePackaging.values();
	}

}
