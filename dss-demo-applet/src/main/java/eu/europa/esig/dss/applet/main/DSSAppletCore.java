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
package eu.europa.esig.dss.applet.main;

import java.io.File;
import java.io.IOException;
import java.net.URL;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.applet.SignatureTokenType;
import eu.europa.esig.dss.applet.controller.ActivityController;
import eu.europa.esig.dss.applet.main.Parameters.AppletUsage;
import eu.europa.esig.dss.applet.model.ActivityModel;
import eu.europa.esig.dss.applet.model.SignatureModel;
import eu.europa.esig.dss.applet.model.ValidationPolicyModel;
import eu.europa.esig.dss.applet.swing.mvc.AppletCore;
import eu.europa.esig.dss.applet.util.DSSStringUtils;
import eu.europa.esig.dss.applet.wizard.signature.SignatureWizardController;
import eu.europa.esig.dss.applet.wizard.validationpolicy.ValidationPolicyWizardController;
import eu.europa.esig.dss.wsclient.signature.SignaturePackaging;

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */
@SuppressWarnings("serial")
public class DSSAppletCore extends AppletCore {

	private static final String PARAM_APPLET_USAGE = "usage";

	private static final String PARAM_SERVICE_URL = "service_url";

	private static final String PARAM_PKCS11_FILE = "pkcs11_file";
	private static final String PARAM_PKCS12_FILE = "pkcs12_file";

	private static final String PARAM_SIGNATURE_POLICY_ALGO = "signature_policy_algo";
	private static final String PARAM_SIGNATURE_POLICY_HASH = "signature_policy_hash";

	private static final String PARAM_STRICT_RFC3370 = "strict_rfc3370";

	private static final String PARAM_TOKEN_TYPE = "token_type";

	private static final String PARAM_SIGNATURE_PACKAGING = "signature_packaging";
	private static final String PARAM_SIGNATURE_FORMAT = "signature_format";
	private static final String PARAM_SIGNATURE_LEVEL = "signature_level";

	private static final String PARAM_DEFAULT_POLICY_URL = "default_policy_url";

	private Parameters parameters;

	/**
	 * @return the parameters
	 */
	public Parameters getParameters() {
		return parameters;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.ecodex.dss.commons.swing.mvc.AbstractApplet#layout(javax.swing.JApplet)
	 */
	@Override
	protected void layout(final AppletCore core) {
		getController(ActivityController.class).display();
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.ecodex.dss.commons.swing.mvc.AbstractApplet#registerControllers()
	 */
	@Override
	protected void registerControllers() {
		getControllers().put(ActivityController.class, new ActivityController(this, new ActivityModel()));
		getControllers().put(SignatureWizardController.class, new SignatureWizardController(this, new SignatureModel()));
		getControllers().put(ValidationPolicyWizardController.class, new ValidationPolicyWizardController(this, new ValidationPolicyModel()));
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.ecodex.dss.commons.swing.mvc.applet.AppletCore#registerParameters()
	 */
	@Override
	protected void registerParameters(ParameterProvider parameterProvider) {

		LOG.info("Register applet parameters ");

		final Parameters parameters = new Parameters();

		final String appletUsageParam = parameterProvider.getParameter(PARAM_APPLET_USAGE);
		if (StringUtils.isNotEmpty(appletUsageParam)) {
			parameters.setAppletUsage(AppletUsage.valueOf(appletUsageParam.toUpperCase()));
		}

		final String signatureFormatParam = parameterProvider.getParameter(PARAM_SIGNATURE_FORMAT);
		if (StringUtils.isNotEmpty(signatureFormatParam)) {
			parameters.setSignatureFormat(signatureFormatParam);
			final String signaturePackagingParam = parameterProvider.getParameter(PARAM_SIGNATURE_PACKAGING);
			if (StringUtils.isNotEmpty(signaturePackagingParam)) {
				parameters.setSignaturePackaging(SignaturePackaging.valueOf(signaturePackagingParam));
				final String signatureLevelParam = parameterProvider.getParameter(PARAM_SIGNATURE_LEVEL);
				if (StringUtils.isNotEmpty(signatureLevelParam)) {
					parameters.setSignatureLevel(signatureLevelParam);
				}
			}
		}

		// Service URL
		final String serviceParam = parameterProvider.getParameter(PARAM_SERVICE_URL);
		//        System.out.println(serviceParam);
		if (StringUtils.isEmpty(serviceParam)) {
			throw new IllegalArgumentException(PARAM_SERVICE_URL + " cannot be empty");
		}
		parameters.setServiceURL(serviceParam);

		// Signature Token
		final String tokenParam = parameterProvider.getParameter(PARAM_TOKEN_TYPE);
		if (DSSStringUtils
				.contains(tokenParam, SignatureTokenType.MOCCA.name(), SignatureTokenType.MSCAPI.name(), SignatureTokenType.PKCS11.name(), SignatureTokenType.PKCS12.name())) {
			parameters.setSignatureTokenType(SignatureTokenType.valueOf(tokenParam));
		} else {
			LOG.warn("Invalid value of " + PARAM_TOKEN_TYPE + " parameter: {}", tokenParam);
		}

		// RFC3370
		final String rfc3370Param = parameterProvider.getParameter(PARAM_STRICT_RFC3370);
		if (StringUtils.isNotEmpty(rfc3370Param)) {
			try {
				parameters.setStrictRFC3370(Boolean.parseBoolean(rfc3370Param));
			} catch (final Exception e) {
				LOG.warn("Invalid value of " + PARAM_STRICT_RFC3370 + " parameter: {}", rfc3370Param);
			}
		}

		// File path PKCS11
		final String pkcs11Param = parameterProvider.getParameter(PARAM_PKCS11_FILE);
		if (StringUtils.isNotEmpty(pkcs11Param)) {
			final File file = new File(pkcs11Param);
			if (!file.exists() || file.isFile()) {
				LOG.warn("Invalid value of " + PARAM_PKCS11_FILE + " parameter: {}", pkcs11Param);
			}
			parameters.setPkcs11File(file);
		}

		// File path PKCS12
		final String pkcs12Param = parameterProvider.getParameter(PARAM_PKCS12_FILE);
		if (StringUtils.isNotEmpty(pkcs12Param)) {
			final File file = new File(pkcs12Param);
			if (!file.exists() || file.isFile()) {
				LOG.warn("Invalid value of " + PARAM_PKCS12_FILE + " parameter: {}", pkcs11Param);
			}
			parameters.setPkcs12File(file);
		}

		final String signaturePolicyAlgoParam = parameterProvider.getParameter(PARAM_SIGNATURE_POLICY_ALGO);
		parameters.setSignaturePolicyAlgo(signaturePolicyAlgoParam);

		final String signaturePolicyValueParam = parameterProvider.getParameter(PARAM_SIGNATURE_POLICY_HASH);
		parameters.setSignaturePolicyValue(Base64.decodeBase64(signaturePolicyValueParam));

		// Default policy URL
		final String defaultPolicyUrl = parameterProvider.getParameter(PARAM_DEFAULT_POLICY_URL);
		if (StringUtils.isNotEmpty(defaultPolicyUrl)) {
			try {
				parameters.setDefaultPolicyUrl(new URL(defaultPolicyUrl));
			} catch (IOException e) {
				throw new IllegalArgumentException(PARAM_DEFAULT_POLICY_URL + " cannot be opened", e);
			}
		}

		this.parameters = parameters;

		LOG.info("Parameters - {}", parameters);

	}
}
