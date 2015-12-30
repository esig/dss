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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
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
import org.springframework.web.bind.annotation.SessionAttributes;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureTokenType;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.web.editor.EnumPropertyEditor;
import eu.europa.esig.dss.web.model.SignatureDocumentForm;
import eu.europa.esig.dss.web.service.SigningService;

/**
 * Signature controller
 * With this controller all configurations are in the webapp. The applet is only used to get certificates and to sign
 */
@Controller
@SessionAttributes(value = {
		"signatureDocumentForm", "signedDocument"
})
@RequestMapping(value = "/signature-light-applet")
public class SignatureLightAppletController {

	private static final Logger logger = LoggerFactory.getLogger(SignatureLightAppletController.class);

	private static final String SIGNATURE_PARAMETERS = "signature-parameters";
	private static final String SELECT_CERTIFICATE = "select-certificate";
	private static final String SELECT_CERTIFICATE_PKCS12 = "select-certificate-pkcs12";
	private static final String SIGN_DOCUMENT = "sign-document";
	private static final String SIGNATURE_FINISH = "signature-finish";

	@Autowired
	private SigningService signingService;

	@InitBinder
	public void initBinder(WebDataBinder binder) {
		binder.registerCustomEditor(SignatureForm.class, new EnumPropertyEditor(SignatureForm.class));
		binder.registerCustomEditor(SignaturePackaging.class, new EnumPropertyEditor(SignaturePackaging.class));
		binder.registerCustomEditor(SignatureLevel.class, new EnumPropertyEditor(SignatureLevel.class));
		binder.registerCustomEditor(DigestAlgorithm.class, new EnumPropertyEditor(DigestAlgorithm.class));
		binder.registerCustomEditor(EncryptionAlgorithm.class, new EnumPropertyEditor(EncryptionAlgorithm.class));
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
		// default values
		signatureDocumentForm.setPkcsPath("C:\\Windows\\System32\\beidpkcs11.dll");
		model.addAttribute("signatureDocumentForm", signatureDocumentForm);
		return SIGNATURE_PARAMETERS;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String sendSignatureParameters(Model model, HttpServletRequest request, HttpServletResponse response,
			@ModelAttribute("signatureDocumentForm") @Valid SignatureDocumentForm signatureDocumentForm, BindingResult result) {

		if (result.hasErrors()) {
			return SIGNATURE_PARAMETERS;
		}

		if (SignatureTokenType.PKCS12.equals(signatureDocumentForm.getToken())) {
			try {
				Pkcs12SignatureToken token = new Pkcs12SignatureToken(signatureDocumentForm.getPkcsPassword(), signatureDocumentForm.getPkcsFile().getInputStream());
				List<DSSPrivateKeyEntry> keys = token.getKeys();
				model.addAttribute("keys", keys);
			} catch (IOException e) {
				logger.error("Unable to initialize Pkcs12SignatureToken : " + e.getMessage(), e);
				return SIGNATURE_PARAMETERS;
			}
			return SELECT_CERTIFICATE_PKCS12;
		} else {
			// certificate selection with applet
			return SELECT_CERTIFICATE;
		}
	}

	@RequestMapping(method = RequestMethod.POST, params = "data-to-sign")
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

	@RequestMapping(method = RequestMethod.POST, params = "sign-document")
	public String signDocument(Model model, HttpServletRequest request, HttpServletResponse response,
			@ModelAttribute("signatureDocumentForm") @Valid SignatureDocumentForm signatureDocumentForm, BindingResult result) throws IOException {
		if (result.hasErrors()) {
			return SIGNATURE_PARAMETERS;
		}

		DSSDocument document = signingService.signDocument(signatureDocumentForm);
		InMemoryDocument signedDocument = new InMemoryDocument(IOUtils.toByteArray(document.openStream()), document.getName(), document.getMimeType());
		model.addAttribute("signedDocument", signedDocument);

		return SIGNATURE_FINISH;
	}

	@RequestMapping(method = RequestMethod.POST, params = "sign-document-pkcs12")
	public String signDocumentPkcs12(Model model, HttpServletRequest request, HttpServletResponse response,
			@ModelAttribute("signatureDocumentForm") @Valid SignatureDocumentForm signatureDocumentForm, BindingResult result) throws IOException {
		if (result.hasErrors()) {
			return SIGNATURE_PARAMETERS;
		}

		DSSDocument document = signingService.signDocumentPKCS12(signatureDocumentForm);
		InMemoryDocument signedDocument = new InMemoryDocument(IOUtils.toByteArray(document.openStream()), document.getName(), document.getMimeType());
		model.addAttribute("signedDocument", signedDocument);

		return SIGNATURE_FINISH;
	}

	@RequestMapping(value = "/download", method = RequestMethod.GET)
	public String downloadSignedFile(@ModelAttribute("signedDocument") InMemoryDocument signedDocument, HttpServletResponse response) {
		try {
			MimeType mimeType = signedDocument.getMimeType();
			if (mimeType != null) {
				response.setContentType(mimeType.getMimeTypeString());
			}
			response.setHeader("Content-Transfer-Encoding", "binary");
			response.setHeader("Content-Disposition", "attachment; filename=\"" + signedDocument.getName() + "\"");
			IOUtils.copy(new ByteArrayInputStream(signedDocument.getBytes()), response.getOutputStream());

		} catch (Exception e) {
			logger.error("An error occured while pushing file in response : " + e.getMessage(), e);
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

	@ModelAttribute("digestAlgos")
	public DigestAlgorithm[] getDigestAlgorithms() {
		DigestAlgorithm[] algos = new DigestAlgorithm[] {
				DigestAlgorithm.SHA1, DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512
		};
		return algos;
	}

	@ModelAttribute("tokenTypes")
	public SignatureTokenType[] getSignatureTokenTypes() {
		SignatureTokenType[] tokenTypes = new SignatureTokenType[] {
				SignatureTokenType.MSCAPI, SignatureTokenType.PKCS11, SignatureTokenType.PKCS12
		};
		return tokenTypes;
	}

}
