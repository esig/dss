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
package eu.europa.esig.dss.ws;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.BLevelParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.x509.SignatureForm;

/**
 * Representation of a <i>SignedProperties</i> Element.
 *
 *
 */

public class WSParameters {

	/**
	 * {@code SignatureLevel}
	 */
	private SignatureLevel signatureLevel;

	private SignaturePackaging signaturePackaging;

	/**
	 * XAdES: ds:CanonicalizationMethod indicate the canonicalization algorithm: Algorithm="...".
	 */
	private String signedInfoCanonicalizationMethod;

	/**
	 * The encryption algorithm shall be automatically extracted from the signing token.
	 */
	private EncryptionAlgorithm encryptionAlgorithm;

	/**
	 * XAdES: The digest algorithm used to hash ds:SignedInfo.
	 */
	private DigestAlgorithm digestAlgorithm;

	private Date signingDate;

	private byte[] signingCertificateBytes;

	/**
	 * This variable indicates if it is possible to sign with an expired certificate.
	 */
	private boolean signWithExpiredCertificate = false;

	private List<WSChainCertificate> chainCertificateList = new ArrayList<WSChainCertificate>();

	private Policy signaturePolicy;

	private DigestAlgorithm signingCertificateDigestAlgorithm = DigestAlgorithm.SHA1;

	private List<String> claimedSignerRole;

	private List<String> certifiedSignerRoles;

	private String contentIdentifierPrefix;
	private String contentIdentifierSuffix;

	private List<String> commitmentTypeIndication;
	private BLevelParameters.SignerLocation signerLocation;

	private DigestAlgorithm timestampDigestAlgorithm;

	private List<WSDSSReference> references;

	/**
	 * The parameters related to ASiC from of the signature.
	 */
	/**
	 * Indicates if the ZIP comment should be used to store the signed content mime-type.
	 */
	private boolean asicZipComment = false;

	/**
	 * Indicates the mime-type to be set within the mimetype file. If null the stored mime-type is that of the signed content.
	 */
	private String asicMimeType = null;

	/**
	 * The default signature form to use within the ASiC containers.
	 */
	private SignatureForm asicSignatureForm = SignatureForm.XAdES;

	/**
	 * This variable contains already enclosed signature(s) when appending a new one.
	 */
	private WSDocument asicEnclosedSignature;


	/**
	 * @return
	 */
	public SignatureLevel getSignatureLevel() {
		return signatureLevel;
	}

	/**
	 * @param signatureLevel
	 */
	public void setSignatureLevel(final SignatureLevel signatureLevel) {
		this.signatureLevel = signatureLevel;
	}

	/**
	 * @return
	 */
	public SignaturePackaging getSignaturePackaging() {
		return signaturePackaging;
	}

	/**
	 * @param signaturePackaging
	 */
	public void setSignaturePackaging(final SignaturePackaging signaturePackaging) {
		this.signaturePackaging = signaturePackaging;
	}

	/**
	 * @return
	 */
	public String getSignedInfoCanonicalizationMethod() {
		return signedInfoCanonicalizationMethod;
	}

	/**
	 * @param signedInfoCanonicalizationMethod
	 */
	public void setSignedInfoCanonicalizationMethod(String signedInfoCanonicalizationMethod) {
		this.signedInfoCanonicalizationMethod = signedInfoCanonicalizationMethod;
	}

	/**
	 * @return
	 */
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		return encryptionAlgorithm;
	}

	/**
	 * @param encryptionAlgorithm
	 */
	public void setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
		this.encryptionAlgorithm = encryptionAlgorithm;
	}

	/**
	 * @return
	 */
	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	/**
	 * @param digestAlgorithm
	 */
	public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
	}

	/**
	 * @return
	 */
	public Date getSigningDate() {
		return signingDate;
	}

	/**
	 * @param signingDate
	 */
	public void setSigningDate(final Date signingDate) {
		this.signingDate = signingDate;
	}

	/**
	 * @return
	 */
	public byte[] getSigningCertificateBytes() {
		return signingCertificateBytes;
	}

	/**
	 * @param signingCertificateBytes
	 */
	public void setSigningCertificateBytes(final byte[] signingCertificateBytes) {
		this.signingCertificateBytes = signingCertificateBytes;
	}

	/**
	 * @return
	 */
	public boolean getSignWithExpiredCertificate() {
		return signWithExpiredCertificate;
	}

	/**
	 * @param signWithExpiredCertificate
	 */
	public void setSignWithExpiredCertificate(boolean signWithExpiredCertificate) {
		this.signWithExpiredCertificate = signWithExpiredCertificate;
	}

	/**
	 * @return
	 */
	public List<WSChainCertificate> getChainCertificateList() {
		return chainCertificateList;
	}

	/**
	 * @param chainCertificateList
	 */
	public void setChainCertificateList(final List<WSChainCertificate> chainCertificateList) {
		this.chainCertificateList = chainCertificateList;
	}

	/**
	 * @return
	 */
	public Policy getSignaturePolicy() {
		return signaturePolicy;
	}

	/**
	 * @param signaturePolicy
	 */
	public void setSignaturePolicy(final Policy signaturePolicy) {
		this.signaturePolicy = signaturePolicy;
	}

	public DigestAlgorithm getSigningCertificateDigestAlgorithm() {
		return signingCertificateDigestAlgorithm;
	}

	public void setSigningCertificateDigestAlgorithm(DigestAlgorithm signingCertificateDigestAlgorithm) {
		this.signingCertificateDigestAlgorithm = signingCertificateDigestAlgorithm;
	}

	public List<String> getClaimedSignerRole() {
		return claimedSignerRole;
	}

	public void setClaimedSignerRole(List<String> claimedSignerRole) {
		this.claimedSignerRole = claimedSignerRole;
	}

	public List<String> getCertifiedSignerRoles() {
		return certifiedSignerRoles;
	}

	public void setCertifiedSignerRoles(List<String> certifiedSignerRoles) {
		this.certifiedSignerRoles = certifiedSignerRoles;
	}

	public String getContentIdentifierPrefix() {
		return contentIdentifierPrefix;
	}

	public void setContentIdentifierPrefix(String contentIdentifierPrefix) {
		this.contentIdentifierPrefix = contentIdentifierPrefix;
	}

	public String getContentIdentifierSuffix() {
		return contentIdentifierSuffix;
	}

	public void setContentIdentifierSuffix(String contentIdentifierSuffix) {
		this.contentIdentifierSuffix = contentIdentifierSuffix;
	}

	public List<String> getCommitmentTypeIndication() {
		return commitmentTypeIndication;
	}

	public void setCommitmentTypeIndication(List<String> commitmentTypeIndication) {
		this.commitmentTypeIndication = commitmentTypeIndication;
	}

	public BLevelParameters.SignerLocation getSignerLocation() {
		return signerLocation;
	}

	public void setSignerLocation(BLevelParameters.SignerLocation signerLocation) {
		this.signerLocation = signerLocation;
	}

	public DigestAlgorithm getTimestampDigestAlgorithm() {
		return timestampDigestAlgorithm;
	}

	public void setTimestampDigestAlgorithm(DigestAlgorithm timestampDigestAlgorithm) {
		this.timestampDigestAlgorithm = timestampDigestAlgorithm;
	}

	public List<WSDSSReference> getReferences() {
		return references;
	}

	public void setReferences(List<WSDSSReference> references) {

		this.references = references;
	}

	public boolean getAsicZipComment() {
		return asicZipComment;
	}

	public void setAsicZipComment(boolean asicZipComment) {
		this.asicZipComment = asicZipComment;
	}

	public String getAsicMimeType() {
		return asicMimeType;
	}

	public void setAsicMimeType(String asicMimeType) {
		this.asicMimeType = asicMimeType;
	}

	public SignatureForm getAsicSignatureForm() {
		return asicSignatureForm;
	}

	public void setAsicSignatureForm(SignatureForm asicSignatureForm) {
		this.asicSignatureForm = asicSignatureForm;
	}

	public WSDocument getAsicEnclosedSignature() {
		return asicEnclosedSignature;
	}

	public void setAsicEnclosedSignature(DSSDocument asicEnclosedSignature) {

		this.asicEnclosedSignature = new WSDocument(asicEnclosedSignature);
	}
}