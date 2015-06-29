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
package eu.europa.esig.dss.applet.model;

import java.io.File;
import java.util.Collections;
import java.util.List;

import org.apache.commons.lang.builder.ReflectionToStringBuilder;

import com.jgoodies.binding.beans.Model;

import eu.europa.esig.dss.applet.SignatureTokenType;
import eu.europa.esig.dss.applet.main.FileType;
import eu.europa.esig.dss.applet.util.FileTypeDetectorUtils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.wsclient.signature.DigestAlgorithm;
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
@SuppressWarnings("serial")
public class SignatureModel extends Model {

	public static final String PROPERTY_SELECTED_FILE = "selectedFile";
	private File selectedFile;

	public static final String PROPERTY_TARGET_FILE = "targetedFile";
	private File targetFile;

	public static final String PROPERTY_PKCS11_FILE = "pkcs11File";
	private File pkcs11File;

	public static final String PROPERTY_PKCS12_FILE = "pkcs12File";
	private File pkcs12File;

	public static final String PROPERTY_PKCS11_PASSWORD = "pkcs11Password";
	private String pkcs11Password;

	public static final String PROPERTY_PKCS12_PASSWORD = "pkcs12Password";
	private String pkcs12Password;

	public static final String PROPERTY_TOKEN_TYPE = "tokenType";
	private SignatureTokenType tokenType;

	public static final String PROPERTY_FORMAT = "format";
	private String format;

	public static final String PROPERTY_PACKAGING = "packaging";
	private SignaturePackaging packaging;

	public static final String PROPERTY_LEVEL = "level";
	private String level;

	private SignatureTokenConnection tokenConnection;

	public static final String PROPERTY_PRIVATE_KEYS = "privateKeys";
	private List<DSSPrivateKeyEntry> privateKeys;

	public static final String PROPERTY_SELECTED_PRIVATE_KEY = "selectedPrivateKey";
	private DSSPrivateKeyEntry selectedPrivateKey;

	public static final String PROPERTY_CLAIMED_ROLE = "claimedRole";
	private String claimedRole;

	public static final String PROPERTY_CLAIMED_CHECK = "claimedCheck";
	private boolean claimedCheck;

	public static final String PROPERTY_TSL_SIGNATURE_CHECK = "tslSignatureCheck";
	private boolean tslSignatureCheck;

	public static final String PROPERTY_SIGNATURE_POLICY_CHECK = "signaturePolicyCheck";
	private boolean signaturePolicyCheck;

	public boolean signaturePolicyVisible;

	public static final String PROPERTY_POLICY_ID = "signaturePolicyId";
	private String signaturePolicyId;

	public static final String PROPERTY_POLICY_VALUE = "signaturePolicyValue";

	private String signaturePolicyValue;

	public static final String PROPERTY_POLICY_ALGO = "signaturePolicyAlgo";
	private String signaturePolicyAlgo;

	public static final String PROPERTY_SIGNATURE_DIGEST_ALGORITHM = "signatureDigestAlgorithm";
	private DigestAlgorithm signatureDigestAlgorithm;

	/**
	 * @return the claimedRole
	 */
	public String getClaimedRole() {
		return claimedRole;
	}

	public DigestAlgorithm getSignatureDigestAlgorithm() {
		return signatureDigestAlgorithm;
	}

	public void setSignatureDigestAlgorithm(DigestAlgorithm signatureDigestAlgorithm) {
		final DigestAlgorithm oldValue = this.signatureDigestAlgorithm;
		final DigestAlgorithm newValue = signatureDigestAlgorithm;
		this.signatureDigestAlgorithm = newValue;
		firePropertyChange(PROPERTY_SIGNATURE_DIGEST_ALGORITHM, oldValue, newValue);
	}

	/**
	 * @return the fileType
	 */
	public FileType getFileType() {
		return FileTypeDetectorUtils.resolveFiletype(getSelectedFile());
	}

	/**
	 * @return the format
	 */
	public String getFormat() {
		return format;
	}

	/**
	 * @return the level
	 */
	public String getLevel() {
		return level;
	}

	/**
	 * @return the packaging
	 */
	public SignaturePackaging getPackaging() {
		return packaging;
	}

	/**
	 * @return the pkcs11File
	 */
	public File getPkcs11File() {
		return pkcs11File;
	}

	/**
	 * @return the pkcs11password
	 */
	public String getPkcs11Password() {
		return pkcs11Password;
	}

	/**
	 * @return the pkcs12File
	 */
	public File getPkcs12File() {
		return pkcs12File;
	}

	/**
	 * @return the pkcs12Password
	 */
	public String getPkcs12Password() {
		return pkcs12Password;
	}

	/**
	 * @return the privateKeys
	 */
	public List<DSSPrivateKeyEntry> getPrivateKeys() {

		if ((tokenConnection == null) || (privateKeys == null)) {
			return Collections.<DSSPrivateKeyEntry> emptyList();
		}

		return privateKeys;

	}

	/**
	 * @return the selectedFile
	 */
	public File getSelectedFile() {
		return selectedFile;
	}

	/**
	 * @return the selectedPrivateKey
	 */
	public DSSPrivateKeyEntry getSelectedPrivateKey() {
		return selectedPrivateKey;
	}

	/**
	 * @return the signaturePolicyAlgo
	 */
	public String getSignaturePolicyAlgo() {
		return signaturePolicyAlgo;
	}

	/**
	 * @return the signaturePolicyId
	 */
	public String getSignaturePolicyId() {
		return signaturePolicyId;
	}

	/**
	 * @return the signaturePolicyValue
	 */
	public String getSignaturePolicyValue() {
		return signaturePolicyValue;
	}

	/**
	 * @return the targetFile
	 */
	public File getTargetFile() {
		return targetFile;
	}

	/**
	 * @return the tokenConnection
	 */
	public SignatureTokenConnection getTokenConnection() {
		return tokenConnection;
	}

	/**
	 * @return the tokenType
	 */
	public SignatureTokenType getTokenType() {
		return tokenType;
	}

	/**
	 * @return the claimedCheck
	 */
	public boolean isClaimedCheck() {
		return claimedCheck;
	}

	/**
	 * @return the signaturePolicyCheck
	 */
	public boolean isSignaturePolicyCheck() {
		return signaturePolicyCheck;
	}

	public boolean isSignaturePolicyVisible() {
		return signaturePolicyVisible;
	}

	/**
	 * @param claimedCheck the claimedCheck to set
	 */
	public void setClaimedCheck(final boolean claimedCheck) {
		final boolean oldValue = this.claimedCheck;
		final boolean newValue = claimedCheck;
		this.claimedCheck = newValue;
		firePropertyChange(PROPERTY_CLAIMED_CHECK, oldValue, newValue);
	}

	/**
	 * @param claimedRole the claimedRole to set
	 */
	public void setClaimedRole(final String claimedRole) {
		final String oldValue = this.claimedRole;
		final String newValue = claimedRole;
		this.claimedRole = newValue;
		firePropertyChange(PROPERTY_CLAIMED_ROLE, oldValue, newValue);
	}

	/**
	 *
	 * @return tslSignatureCheck
	 */
	public boolean isTslSignatureCheck() {
		return tslSignatureCheck;
	}

	/**
	 *
	 * @param tslSignatureCheck the tslSignatureCheck to set
	 */
	public void setTslSignatureCheck(boolean tslSignatureCheck) {
		this.tslSignatureCheck = tslSignatureCheck;
		final boolean oldValue = this.tslSignatureCheck;
		final boolean newValue = tslSignatureCheck;
		this.tslSignatureCheck = newValue;
		firePropertyChange(PROPERTY_TSL_SIGNATURE_CHECK, oldValue, newValue);

	}

	/**
	 * @param format the format to set
	 */
	public void setFormat(final String format) {
		final String oldValue = this.format;
		final String newValue = format;
		this.format = newValue;
		firePropertyChange(PROPERTY_FORMAT, oldValue, newValue);
	}

	/**
	 * @param level the level to set
	 */
	public void setLevel(final String level) {
		final String oldValue = this.level;
		final String newValue = level;
		this.level = newValue;
		firePropertyChange(PROPERTY_LEVEL, oldValue, newValue);
	}

	/**
	 * @param packaging the packaging to set
	 */
	public void setPackaging(final SignaturePackaging packaging) {
		final SignaturePackaging oldValue = this.packaging;
		final SignaturePackaging newValue = packaging;
		this.packaging = newValue;
		firePropertyChange(PROPERTY_SELECTED_FILE, oldValue, newValue);
	}

	/**
	 * @param pkcs11File the pkcs11File to set
	 */
	public void setPkcs11File(final File pkcs11File) {
		final File oldValue = this.pkcs11File;
		final File newValue = pkcs11File;
		this.pkcs11File = newValue;
		firePropertyChange(PROPERTY_PKCS11_FILE, oldValue, newValue);
	}

	/**
	 *
	 * @param pkcs11Password the pkcs11password to set
	 */
	public void setPkcs11Password(final String pkcs11Password) {
		final String oldValue = this.pkcs11Password;
		final String newValue = pkcs11Password;
		this.pkcs11Password = newValue;
		firePropertyChange(PROPERTY_PKCS11_PASSWORD, oldValue, newValue);
	}

	/**
	 * @param pkcs12File the pkcs12File to set
	 */
	public void setPkcs12File(final File pkcs12File) {
		final File oldValue = this.pkcs12File;
		final File newValue = pkcs12File;
		this.pkcs12File = newValue;
		firePropertyChange(PROPERTY_PKCS12_FILE, oldValue, newValue);
	}

	/**
	 * @param pkcs12Password the pkcs12Password to set
	 */
	public void setPkcs12Password(final String pkcs12Password) {
		final String oldValue = this.pkcs12Password;
		final String newValue = pkcs12Password;
		this.pkcs12Password = newValue;
		firePropertyChange(PROPERTY_PKCS12_PASSWORD, oldValue, newValue);
	}

	/**
	 * @param privateKeys the privateKeys to set
	 */
	public void setPrivateKeys(final List<DSSPrivateKeyEntry> privateKeys) {
		final List<DSSPrivateKeyEntry> oldValue = this.privateKeys;
		final List<DSSPrivateKeyEntry> newValue = privateKeys;
		this.privateKeys = newValue;
		firePropertyChange(PROPERTY_PRIVATE_KEYS, oldValue, newValue);
	}

	/**
	 * @param selectedFile the selectedFile to set
	 */
	public void setSelectedFile(final File selectedFile) {
		final File oldValue = this.selectedFile;
		final File newValue = selectedFile;
		this.selectedFile = newValue;
		firePropertyChange(PROPERTY_SELECTED_FILE, oldValue, newValue);
	}

	/**
	 * @param selectedPrivateKey the selectedPrivateKey to set
	 */
	public void setSelectedPrivateKey(final DSSPrivateKeyEntry selectedPrivateKey) {
		final DSSPrivateKeyEntry oldValue = this.selectedPrivateKey;
		final DSSPrivateKeyEntry newValue = selectedPrivateKey;
		this.selectedPrivateKey = newValue;
		firePropertyChange(PROPERTY_SELECTED_PRIVATE_KEY, oldValue, newValue);
	}

	/**
	 * @param signaturePolicyAlgo the signaturePolicyAlgo to set
	 */
	public void setSignaturePolicyAlgo(final String signaturePolicyAlgo) {
		final String oldValue = this.signaturePolicyAlgo;
		final String newValue = signaturePolicyAlgo;
		this.signaturePolicyAlgo = newValue;
		firePropertyChange(PROPERTY_POLICY_ALGO, oldValue, newValue);
	}

	/**
	 * @param signaturePolicyCheck the signaturePolicyCheck to set
	 */
	public void setSignaturePolicyCheck(final boolean signaturePolicyCheck) {
		final boolean oldValue = this.signaturePolicyCheck;
		final boolean newValue = signaturePolicyCheck;
		this.signaturePolicyCheck = newValue;
		firePropertyChange(PROPERTY_SIGNATURE_POLICY_CHECK, oldValue, newValue);
	}

	/**
	 * @param signaturePolicyId the signaturePolicyId to set
	 */
	public void setSignaturePolicyId(final String signaturePolicyId) {
		final String oldValue = this.signaturePolicyId;
		final String newValue = signaturePolicyId;
		this.signaturePolicyId = newValue;
		firePropertyChange(PROPERTY_POLICY_ID, oldValue, newValue);
	}

	/**
	 * @param signaturePolicyValue the signaturePolicyValue to set
	 */
	public void setSignaturePolicyValue(final String signaturePolicyValue) {
		final String oldValue = this.signaturePolicyValue;
		final String newValue = signaturePolicyValue;
		this.signaturePolicyValue = newValue;
		firePropertyChange(PROPERTY_POLICY_ALGO, oldValue, newValue);
	}

	public void setSignaturePolicyVisible(boolean signaturePolicyVisible) {
		this.signaturePolicyVisible = signaturePolicyVisible;
	}

	/**
	 * @param targetFile the targetFile to set
	 */
	public void setTargetFile(final File targetFile) {
		final File oldValue = this.targetFile;
		final File newValue = targetFile;
		this.targetFile = newValue;
		firePropertyChange(PROPERTY_TARGET_FILE, oldValue, newValue);
	}

	/**
	 * @param tokenConnection the tokenConnection to set
	 */
	public void setTokenConnection(final SignatureTokenConnection tokenConnection) {
		this.tokenConnection = tokenConnection;
	}

	/**
	 * @param tokenType the tokenType to set
	 */
	public void setTokenType(final SignatureTokenType tokenType) {
		final SignatureTokenType oldValue = this.tokenType;
		final SignatureTokenType newValue = tokenType;
		this.tokenType = newValue;
		firePropertyChange(PROPERTY_TOKEN_TYPE, oldValue, newValue);
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
