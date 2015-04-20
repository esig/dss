package eu.europa.esig.dss.web.controller;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.web.WebAppUtils;
import eu.europa.esig.dss.web.editor.EnumPropertyEditor;
import eu.europa.esig.dss.web.model.ExtensionForm;
import eu.europa.esig.dss.web.service.SigningService;
import eu.europa.esig.dss.x509.SignatureForm;

@Controller
@RequestMapping(value = "/extension")
public class ExtensionController {

	private static final Logger logger = LoggerFactory.getLogger(ExtensionController.class);

	private static final String EXTENSION_TILE = "extension";

	@Autowired
	private SigningService signingService;

	@InitBinder
	public void initBinder(WebDataBinder binder) {
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
	public String extend(HttpServletRequest request, HttpServletResponse response, @ModelAttribute("extensionForm") @Valid ExtensionForm extensionForm, BindingResult result) {
		if (result.hasErrors()) {
			return EXTENSION_TILE;
		}

		DSSDocument toExtendDocument = WebAppUtils.toDSSDocument(extensionForm.getSignedFile());
		DSSDocument extendedDocument = signingService.extend(extensionForm.getSignatureForm(), extensionForm.getSignaturePackaging(), extensionForm.getSignatureLevel(), toExtendDocument, WebAppUtils.toDSSDocument(extensionForm.getOriginalFile()));

		String originalName = toExtendDocument.getName();
		String extendedFileName = StringUtils.substringBeforeLast(originalName, ".") + "-extended."+StringUtils.substringAfterLast(originalName, ".");

		response.setContentType(extendedDocument.getMimeType().getMimeTypeString());
		response.setHeader("Content-Disposition", "attachment; filename=" + extendedFileName);
		try {
			IOUtils.copy(new ByteArrayInputStream(extendedDocument.getBytes()), response.getOutputStream());
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}

		return null;
	}

	@ModelAttribute("signatureForms")
	public SignatureForm[] getSignatureForms() {
		return SignatureForm.values();
	}

	@ModelAttribute("signaturePackagings")
	public SignaturePackaging[] getSignaturePackagings() {
		return SignaturePackaging.values();
	}

	@RequestMapping(value = "/packagingsByForm", produces = MediaType.APPLICATION_JSON_VALUE)
	@ResponseBody
	public List<SignaturePackaging> getAllowedPackagingsByForm(@RequestParam("form") SignatureForm signatureForm) {
		List<SignaturePackaging> packagings = new ArrayList<SignaturePackaging>();
		if (signatureForm != null) {
			switch (signatureForm) {
				case CAdES:
					packagings.add(SignaturePackaging.ENVELOPING);
					packagings.add(SignaturePackaging.DETACHED);
					break;
				case PAdES:
					packagings.add(SignaturePackaging.ENVELOPED);
					break;
				case XAdES:
					packagings.add(SignaturePackaging.ENVELOPED);
					packagings.add(SignaturePackaging.ENVELOPING);
					packagings.add(SignaturePackaging.DETACHED);
					break;
				case ASiC_S:
				case ASiC_E:
					packagings.add(SignaturePackaging.DETACHED);
					break;
				default:
					break;
			}
		}
		return packagings;
	}

	@RequestMapping(value = "/levelsByForm", produces = MediaType.APPLICATION_JSON_VALUE)
	@ResponseBody
	public List<SignatureLevel> getAllowedLevelsByForm(@RequestParam("form") SignatureForm signatureForm) {
		List<SignatureLevel> levels = new ArrayList<SignatureLevel>();
		if (signatureForm != null) {
			switch (signatureForm) {
				case CAdES:
					levels.add(SignatureLevel.CAdES_BASELINE_T);
					levels.add(SignatureLevel.CAdES_BASELINE_LT);
					levels.add(SignatureLevel.CAdES_BASELINE_LTA);
					break;
				case PAdES:
					levels.add(SignatureLevel.PAdES_BASELINE_T);
					levels.add(SignatureLevel.PAdES_BASELINE_LT);
					levels.add(SignatureLevel.PAdES_BASELINE_LTA);
					break;
				case XAdES:
					levels.add(SignatureLevel.XAdES_BASELINE_T);
					levels.add(SignatureLevel.XAdES_BASELINE_LT);
					levels.add(SignatureLevel.XAdES_BASELINE_LTA);
					break;
				case ASiC_S:
					levels.add(SignatureLevel.ASiC_S_BASELINE_T);
					levels.add(SignatureLevel.ASiC_S_BASELINE_LT);
					levels.add(SignatureLevel.ASiC_S_BASELINE_LTA);
					break;
				case ASiC_E:
					levels.add(SignatureLevel.ASiC_E_BASELINE_T);
					levels.add(SignatureLevel.ASiC_E_BASELINE_LT);
					levels.add(SignatureLevel.ASiC_E_BASELINE_LTA);
					break;
				default:
					break;
			}
		}
		return levels;
	}

}
