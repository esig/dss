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
import java.net.URL;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.builder.ReflectionToStringBuilder;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.applet.JavaPreferencesDAO;
import eu.europa.esig.dss.applet.SignatureTokenType;
import eu.europa.esig.dss.applet.UserPreferencesDAO;
import eu.europa.esig.dss.validation.ValidationResourceManager;
import eu.europa.esig.dss.wsclient.signature.SignaturePackaging;

/**
 *
 * TODO
 *
 *
 *
 *
 *
 *
 */
public class Parameters {


	public enum AppletUsage {
		ALL, SIGN, EDIT_VALIDATION_POLICY
	}

	private AppletUsage appletUsage = AppletUsage.ALL;

	/**
	 *
	 */
	private final UserPreferencesDAO userPreferencesDAO = new JavaPreferencesDAO();

	/**
	 *
	 */
	private boolean strictRFC3370;
	/**
	 *
	 */
	private File pkcs11File;
	/**
	 *
	 */
	private File pkcs12File;

	/**
	 *
	 */
	private SignatureTokenType signatureTokenType;

	/**
	 *
	 */
	private String signaturePolicyAlgo;
	/**
	 *
	 */
	private byte[] signaturePolicyValue;

	/**
	 *
	 */
	private String serviceURL;

	/**
	 *
	 */
	private SignaturePackaging signaturePackaging;

	/**
	 *
	 */
	private String signatureFormat;
	/**
	 *
	 */
	private String signatureLevel;

	private URL defaultPolicyUrl;

	private URL defaultXsdPolicyUrl;

	/**
	 *
	 * The default constructor for Parameters.
	 */
	public Parameters() {

	}

	public AppletUsage getAppletUsage() {
		return appletUsage;
	}

	/**
	 * @return the pkcs11File
	 */
	public File getPkcs11File() {
		if (pkcs11File == null) {
			final String path = userPreferencesDAO.getPKCS11LibraryPath();
			if (StringUtils.isNotEmpty(path)) {
				pkcs11File = new File(path);
			}
		}
		return pkcs11File;
	}

	/**
	 * @return the pkcs12File
	 */
	public File getPkcs12File() {
		if (pkcs12File == null) {
			final String path = userPreferencesDAO.getPKCS12FilePath();
			if (StringUtils.isNotEmpty(path)) {
				pkcs12File = new File(path);
			}
		}
		return pkcs12File;
	}

	/**
	 * @return the serviceURL
	 */
	public String getServiceURL() {
		return serviceURL;
	}

	public String getSignatureFormat() {
		return signatureFormat;
	}

	public String getSignatureLevel() {
		return signatureLevel;
	}

	public SignaturePackaging getSignaturePackaging() {
		return signaturePackaging;
	}

	/**
	 * @return the signaturePolicyAlgo
	 */
	public String getSignaturePolicyAlgo() {
		return signaturePolicyAlgo;
	}

	/**
	 * @return the signaturePolicyValue
	 */
	public byte[] getSignaturePolicyValue() {
		if (signaturePolicyValue == null) {
			signaturePolicyValue = DSSUtils.EMPTY_BYTE_ARRAY;
		}
		return signaturePolicyValue;
	}

	/**
	 * @return the signatureTokenType
	 */
	public SignatureTokenType getSignatureTokenType() {
		if (signatureTokenType == null) {
			signatureTokenType = userPreferencesDAO.getSignatureTokenType();
		}
		return signatureTokenType;
	}

	/**
	 *
	 * @return
	 */
	public boolean hasPkcs11File() {
		final File file = getPkcs11File();
		return (file != null) && file.exists() && file.isFile();
	}

	/**
	 *
	 * @return
	 */
	public boolean hasPkcs12File() {
		final File file = getPkcs12File();
		return (file != null) && file.exists() && file.isFile();
	}

	/**
	 *
	 * @return
	 */
	public boolean hasSignaturePolicyAlgo() {
		return StringUtils.isNotEmpty(signaturePolicyAlgo);
	}

	/**
	 *
	 * @return
	 */
	public boolean hasSignaturePolicyValue() {
		return getSignaturePolicyValue().length != 0;
	}

	/**
	 *
	 * @return
	 */
	public boolean hasSignatureTokenType() {
		return signatureTokenType != null;
	}

	/**
	 * @return the strictRFC3370
	 */
	public boolean isStrictRFC3370() {
		return strictRFC3370;
	}

	public void setAppletUsage(AppletUsage appletUsage) {
		this.appletUsage = appletUsage;
	}


	/**
	 * @param pkcs11File the pkcs11File to set
	 */
	public void setPkcs11File(final File pkcs11File) {
		if (pkcs11File != null) {
			userPreferencesDAO.setPKCS12FilePath(pkcs11File.getAbsolutePath());
		}
		this.pkcs11File = pkcs11File;
	}

	/**
	 * @param pkcs12File the pkcs12File to set
	 */
	public void setPkcs12File(final File pkcs12File) {
		if (pkcs12File != null) {
			userPreferencesDAO.setPKCS11LibraryPath(pkcs12File.getAbsolutePath());
		}
		this.pkcs12File = pkcs12File;
	}

	/**
	 * @param serviceURL the serviceURL to set
	 */
	public void setServiceURL(final String serviceURL) {
		this.serviceURL = serviceURL;
	}

	public void setSignatureFormat(String signatureFormat) {
		this.signatureFormat = signatureFormat;
	}

	public void setSignatureLevel(String signatureLevel) {
		this.signatureLevel = signatureLevel;
	}

	public void setSignaturePackaging(SignaturePackaging signaturePackaging) {
		this.signaturePackaging = signaturePackaging;
	}

	/**
	 * @param signaturePolicyAlgo the signaturePolicyAlgo to set
	 */
	public void setSignaturePolicyAlgo(final String signaturePolicyAlgo) {
		this.signaturePolicyAlgo = signaturePolicyAlgo;
	}

	/**
	 * @param signaturePolicyValue the signaturePolicyValue to set
	 */
	public void setSignaturePolicyValue(final byte[] signaturePolicyValue) {
		this.signaturePolicyValue = signaturePolicyValue;
	}

	/**
	 * @param signatureTokenType the signatureTokenType to set
	 */
	public void setSignatureTokenType(final SignatureTokenType signatureTokenType) {
		if (signatureTokenType != null) {
			userPreferencesDAO.setSignatureTokenType(signatureTokenType);
		}
		this.signatureTokenType = signatureTokenType;
	}

	/**
	 * @param strictRFC3370 the strictRFC3370 to set
	 */
	public void setStrictRFC3370(final boolean strictRFC3370) {
		this.strictRFC3370 = strictRFC3370;
	}

	/**
	 * Set the default policy URL for validation. Can be null.
	 * @param defaultPolicyUrl
	 */
	public void setDefaultPolicyUrl(URL defaultPolicyUrl) {
		this.defaultPolicyUrl = defaultPolicyUrl;
	}

	/**
	 *
	 * @return the defaultPolicyUrl for validation. Can be null.
	 */
	public URL getDefaultPolicyUrl() {
		if (defaultPolicyUrl == null) {
			return getClass().getResource(ValidationResourceManager.defaultPolicyConstraintsLocation);
		} else {
			return defaultPolicyUrl;
		}
	}

	/**
	 * Set the default xsd policy URL for validation. Can be null.
	 * @param defaultXsdPolicyUrl
	 */
	public void setDefaultXsdPolicyUrl(URL defaultXsdPolicyUrl) {
		this.defaultXsdPolicyUrl = defaultXsdPolicyUrl;
	}

	/**
	 *
	 * @return the defaultXsdPolicyUrl for validation. Can be null.
	 */
	public URL getDefaultXsdPolicyUrl() {
		if (defaultXsdPolicyUrl == null) {
			return getClass().getResource(ValidationResourceManager.defaultPolicyXsdLocation);
		} else {
			return defaultXsdPolicyUrl;
		}
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return ReflectionToStringBuilder.reflectionToString(this);
	}
}
