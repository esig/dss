/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.applet.main;

import java.io.File;
import java.io.IOException;
import java.net.URL;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.applet.controller.ActivityController;
import eu.europa.ec.markt.dss.applet.main.Parameters.AppletUsage;
import eu.europa.ec.markt.dss.applet.model.ActivityModel;
import eu.europa.ec.markt.dss.applet.model.ExtendSignatureModel;
import eu.europa.ec.markt.dss.applet.model.SignatureModel;
import eu.europa.ec.markt.dss.applet.model.ValidationModel;
import eu.europa.ec.markt.dss.applet.model.ValidationPolicyModel;
import eu.europa.ec.markt.dss.applet.util.DSSStringUtils;
import eu.europa.ec.markt.dss.applet.wizard.extension.ExtensionWizardController;
import eu.europa.ec.markt.dss.applet.wizard.signature.SignatureWizardController;
import eu.europa.ec.markt.dss.applet.wizard.validation.ValidationWizardController;
import eu.europa.ec.markt.dss.applet.wizard.validationpolicy.ValidationPolicyWizardController;
import eu.europa.ec.markt.dss.common.SignatureTokenType;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.AppletCore;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;

/**
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
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
        getControllers().put(ValidationWizardController.class, new ValidationWizardController(this, new ValidationModel()));
        getControllers().put(SignatureWizardController.class, new SignatureWizardController(this, new SignatureModel()));
        getControllers().put(ExtensionWizardController.class, new ExtensionWizardController(this, new ExtendSignatureModel()));
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
        if (DSSUtils.isNotEmpty(appletUsageParam)) {
            parameters.setAppletUsage(AppletUsage.valueOf(appletUsageParam.toUpperCase()));
        }

        final String signatureFormatParam = parameterProvider.getParameter(PARAM_SIGNATURE_FORMAT);
        if (!DSSUtils.isEmpty(signatureFormatParam)) {
            parameters.setSignatureFormat(signatureFormatParam);
            final String signaturePackagingParam = parameterProvider.getParameter(PARAM_SIGNATURE_PACKAGING);
            if (!DSSUtils.isEmpty(signaturePackagingParam)) {
                parameters.setSignaturePackaging(SignaturePackaging.valueOf(signaturePackagingParam));
                final String signatureLevelParam = parameterProvider.getParameter(PARAM_SIGNATURE_LEVEL);
                if (!DSSUtils.isEmpty(signatureLevelParam)) {
                    parameters.setSignatureLevel(signatureLevelParam);
                }
            }
        }

        // Service URL
        final String serviceParam = parameterProvider.getParameter(PARAM_SERVICE_URL);
        System.out.println(serviceParam);
        if (DSSUtils.isEmpty(serviceParam)) {
            throw new IllegalArgumentException(PARAM_SERVICE_URL + "cannot be empty");
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
        if (DSSUtils.isNotEmpty(rfc3370Param)) {
            try {
                parameters.setStrictRFC3370(Boolean.parseBoolean(rfc3370Param));
            } catch (final Exception e) {
                LOG.warn("Invalid value of " + PARAM_STRICT_RFC3370 + " parameter: {}", rfc3370Param);
            }
        }

        // File path PKCS11
        final String pkcs11Param = parameterProvider.getParameter(PARAM_PKCS11_FILE);
        if (DSSUtils.isNotEmpty(pkcs11Param)) {
            final File file = new File(pkcs11Param);
            if (!file.exists() || file.isFile()) {
                LOG.warn("Invalid value of " + PARAM_PKCS11_FILE + " parameter: {}", pkcs11Param);
            }
            parameters.setPkcs11File(file);
        }

        // File path PKCS12
        final String pkcs12Param = parameterProvider.getParameter(PARAM_PKCS12_FILE);
        if (DSSUtils.isNotEmpty(pkcs12Param)) {
            final File file = new File(pkcs12Param);
            if (!file.exists() || file.isFile()) {
                LOG.warn("Invalid value of " + PARAM_PKCS12_FILE + " parameter: {}", pkcs11Param);
            }
            parameters.setPkcs12File(file);
        }

        final String signaturePolicyAlgoParam = parameterProvider.getParameter(PARAM_SIGNATURE_POLICY_ALGO);
        parameters.setSignaturePolicyAlgo(signaturePolicyAlgoParam);

        final String signaturePolicyValueParam = parameterProvider.getParameter(PARAM_SIGNATURE_POLICY_HASH);
        parameters.setSignaturePolicyValue(DSSUtils.base64Decode(signaturePolicyValueParam));

        // Default policy URL
        final String defaultPolicyUrl = parameterProvider.getParameter(PARAM_DEFAULT_POLICY_URL);
        if (DSSUtils.isNotEmpty(defaultPolicyUrl)) {
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
