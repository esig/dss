/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.web.controller;

import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureTokenType;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.web.editor.EnumPropertyEditor;
import eu.europa.esig.dss.web.model.SignatureDocumentForm;
import eu.europa.esig.dss.web.service.SigningService;

/**
 * Signature controller
 * With this controller all configurations are in the webapp. The applet is only used to get certificates and to sign
 */
@Controller
@SessionAttributes(value = {
		"signatureDocumentForm"
})
@RequestMapping(value = "/signature")
public class SignatureController {

	private static final String SIGNATURE_PARAMETERS = "signature-parameters";
	private static final String SELECT_CERTIFICATE = "select-certificate";
	private static final String SIGN_DOCUMENT = "sign-document";

	@Autowired
	private SigningService signingService;

	@InitBinder
	public void initBinder(WebDataBinder binder) {
		binder.registerCustomEditor(SignatureForm.class, new EnumPropertyEditor(SignatureForm.class));
		binder.registerCustomEditor(SignaturePackaging.class, new EnumPropertyEditor(SignaturePackaging.class));
		binder.registerCustomEditor(SignatureLevel.class, new EnumPropertyEditor(SignatureLevel.class));
		binder.registerCustomEditor(DigestAlgorithm.class, new EnumPropertyEditor(DigestAlgorithm.class));
		binder.registerCustomEditor(SignatureTokenType.class, new EnumPropertyEditor(SignatureTokenType.class));
	}

	/**
	 * @param model
	 *            The model attributes
	 * @return a view name
	 */
	@RequestMapping(method = RequestMethod.GET)
	public String showSignatureParameters(Model model, HttpServletRequest request) {
		SignatureDocumentForm signatureDocumentForm = new SignatureDocumentForm();
		model.addAttribute("signatureDocumentForm", signatureDocumentForm);
		return SIGNATURE_PARAMETERS;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String sendSignatureParameters(HttpServletRequest request, HttpServletResponse response,
			@ModelAttribute("signatureDocumentForm") @Valid SignatureDocumentForm signatureDocumentForm, BindingResult result) {
		if (result.hasErrors()) {
			return SIGNATURE_PARAMETERS;
		}

		return SELECT_CERTIFICATE;
	}

	@RequestMapping(method = RequestMethod.POST, params = "certificate")
	public String getDataToSign(Model model, HttpServletRequest request, HttpServletResponse response,
			@ModelAttribute("signatureDocumentForm") @Valid SignatureDocumentForm signatureDocumentForm, BindingResult result) {
		if (result.hasErrors()) {
			return SIGNATURE_PARAMETERS;
		}

		signatureDocumentForm.setSigningDate(new Date());
		model.addAttribute("signatureDocumentForm", signatureDocumentForm);

		ToBeSigned dataToSign = signingService.getDataToSign(signatureDocumentForm);

		model.addAttribute("digest", Base64.encodeBase64String(dataToSign.getBytes()));

		return SIGN_DOCUMENT;
	}

	@ModelAttribute("signatureForms")
	public SignatureForm[] getSignatureForms() {
		return SignatureForm.values();
	}

	@ModelAttribute("signaturePackagings")
	public SignaturePackaging[] getSignaturePackagings() {
		return SignaturePackaging.values();
	}

	@ModelAttribute("digestAlgos")
	public DigestAlgorithm[] getDigestAlgorithms() {
		return DigestAlgorithm.values();
	}

	@ModelAttribute("tokenTypes")
	public SignatureTokenType[] getSignatureTokenTypes() {
		return SignatureTokenType.values();
	}

}
