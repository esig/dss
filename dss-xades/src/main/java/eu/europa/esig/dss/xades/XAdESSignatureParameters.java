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
package eu.europa.esig.dss.xades;

import java.util.List;

import org.w3c.dom.Document;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.xades.reference.DSSReference;

public class XAdESSignatureParameters extends AbstractSignatureParameters {

	private ProfileParameters context;

	/**
	 * This parameter allows to add optional X509SubjectName in the tag X509Data
	 */
	private boolean addX509SubjectName;

	private List<DSSReference> dssReferences;

	/**
	 * In case of ENVELOPING signature, this parameter allows to include the complete XML and not its base64 encoded
	 * value
	 */
	private boolean embedXML;

	private boolean en319132 = true;

	/**
	 * ds:CanonicalizationMethod indicates the canonicalization algorithm: Algorithm="..." for KeyInfo.
	 */
	private String keyInfoCanonicalizationMethod;

	/**
	 * This parameter allows to produce Manifest signature (https://www.w3.org/TR/xmldsig-core/#sec-o-Manifest).
	 */
	private boolean manifestSignature;

	/**
	 * This attribute is used to inject ASiC root (inclusive canonicalization)
	 */
	private Document rootDocument;

	/**
	 * Optional parameter that contains the canonicalized XML of the XAdES object that was digested,
	 * referenced from the SigningInfo, and indirectly signed when the signature value was created.
	 * If this parameter is specified it will be used in the signed XML document.
	 */
	private byte[] signedAdESObject;

	/**
	 * The digest method used to create the digest of the signer's certificate.
	 */
	private DigestAlgorithm signingCertificateDigestMethod = DigestAlgorithm.SHA512;

	/**
	 * ds:CanonicalizationMethod indicates the canonicalization algorithm: Algorithm="..." for SignedInfo.
	 */
	private String signedInfoCanonicalizationMethod;
	
	/**
	 * Optional parameter defining should the "KeyInfo" element be signed.
	 * If the value of parameter is TRUE, reference of the "KeyInfo" element will be added to "SignedInfo".
	 * FALSE by default.
	 */
	private boolean signKeyInfo = false;

	/**
	 * ds:CanonicalizationMethod indicates the canonicalization algorithm: Algorithm="..." for SignedProperties.
	 */
	private String signedPropertiesCanonicalizationMethod;

	private String xPathLocationString;
	
	/**
	 * If true, prints each signature's tag to a new line with a relevant indent
	 */
	private boolean prettyPrint = false;

	@Override
	public void setSignatureLevel(SignatureLevel signatureLevel) {
		if (signatureLevel == null || SignatureForm.XAdES != signatureLevel.getSignatureForm()) {
			throw new IllegalArgumentException("Only XAdES form is allowed !");
		}
		super.setSignatureLevel(signatureLevel);
	}

	/**
	 * This property is a part of the standard:<br>
	 * 7.2.2 The SigningCertificate element (101 903 V1.4.2 (2010-12) XAdES)<br>
	 * The digest method indicates the digest algorithm to be used to calculate the CertDigest element that contains the
	 * digest for each certificate referenced in the sequence.
	 *
	 * @param signingCertificateDigestMethod
	 */
	public void setSigningCertificateDigestMethod(final DigestAlgorithm signingCertificateDigestMethod) {
		this.signingCertificateDigestMethod = signingCertificateDigestMethod;
	}

	/**
	 * See {@link #setSigningCertificateDigestMethod(DigestAlgorithm)}.
	 *
	 * @return
	 */
	public DigestAlgorithm getSigningCertificateDigestMethod() {
		return signingCertificateDigestMethod;
	}

	/**
	 * @return the canonicalization algorithm to be used when dealing with SignedInfo.
	 */
	public String getSignedInfoCanonicalizationMethod() {
		return signedInfoCanonicalizationMethod;
	}

	/**
	 * Set the canonicalization algorithm to be used when dealing with SignedInfo.
	 *
	 * @param signedInfoCanonicalizationMethod
	 *            the canonicalization algorithm to be used when dealing with SignedInfo.
	 */
	public void setSignedInfoCanonicalizationMethod(final String signedInfoCanonicalizationMethod) {
		this.signedInfoCanonicalizationMethod = signedInfoCanonicalizationMethod;
	}

	/**
	 * @return the canonicalization algorithm to be used when dealing with SignedProperties.
	 */
	public String getSignedPropertiesCanonicalizationMethod() {
		return signedPropertiesCanonicalizationMethod;
	}

	/**
	 * Set the canonicalization algorithm to be used when dealing with SignedProperties.
	 *
	 * @param signedPropertiesCanonicalizationMethod
	 *            the canonicalization algorithm to be used when dealing with SignedInfo.
	 */
	public void setSignedPropertiesCanonicalizationMethod(final String signedPropertiesCanonicalizationMethod) {
		this.signedPropertiesCanonicalizationMethod = signedPropertiesCanonicalizationMethod;
	}
	
	/**
	 * Returns the canonicalization algorithm used for dealing with KeyInfo
	 * @return - name of the canonicalization algorithm
	 */
	public String getKeyInfoCanonicalizationMethod() {
		return keyInfoCanonicalizationMethod;
	}
	
	/**
	 * Set the canonicalization algorithm used for dealing with KeyInfo.
	 * @param keyInfoCanonicalizationMethod - name of the canonicalization algorithm for dealing with KeyInfo.
	 */
	public void setKeyInfoCanonicalizationMethod(final String keyInfoCanonicalizationMethod) {
		this.keyInfoCanonicalizationMethod = keyInfoCanonicalizationMethod;
	}
	
	/**
	 * Returns value value specifying if "KeyInfo" element should be signed.
	 * @return TRUE if "KeyInfo" element must be signed, FALSE otherwise.
	 */
	public boolean isSignKeyInfo() {
		return signKeyInfo;
	}
	
	/**
	 * Set the parameter SignKeyInfo defining if the "KeyInfo" element must be signed and
	 * 		its reference must be included to "SignedInfo" element.
	 * 		The value is FALSE by default.
	 * @param signKeyInfo - if KeyInfo element should be signed
	 */
	public void setSignKeyInfo(boolean signKeyInfo) {
		this.signKeyInfo = signKeyInfo;
	}

	public List<DSSReference> getReferences() {
		return dssReferences;
	}

	public void setReferences(List<DSSReference> references) {
		this.dssReferences = references;
	}

	public String getXPathLocationString() {
		return xPathLocationString;
	}

	/**
	 * Defines the area where the signature will be added (XAdES Enveloped)
	 * 
	 * @param xPathLocationString
	 *            the xpath location of the signature
	 */
	public void setXPathLocationString(String xPathLocationString) {
		this.xPathLocationString = xPathLocationString;
	}

	public Document getRootDocument() {
		return rootDocument;
	}

	public void setRootDocument(Document rootDocument) {
		this.rootDocument = rootDocument;
	}

	public ProfileParameters getContext() {
		if (context == null) {
			context = new ProfileParameters();
		}
		return context;
	}

	public boolean isEn319132() {
		return en319132;
	}

	public void setEn319132(boolean en319132) {
		this.en319132 = en319132;
	}

	public boolean isEmbedXML() {
		return embedXML;
	}

	public void setEmbedXML(boolean embedXML) {
		this.embedXML = embedXML;
	}

	public boolean isManifestSignature() {
		return manifestSignature;
	}

	public void setManifestSignature(boolean manifestSignature) {
		this.manifestSignature = manifestSignature;
	}

	public boolean isAddX509SubjectName() {
		return addX509SubjectName;
	}

	public void setAddX509SubjectName(boolean addX509SubjectName) {
		this.addX509SubjectName = addX509SubjectName;
	}

	public byte[] getSignedAdESObject() {
		return signedAdESObject;
	}

	public void setSignedAdESObject(byte[] signedAdESObject) {
		this.signedAdESObject = signedAdESObject;
	}
	
	public boolean isPrettyPrint() {
		return prettyPrint;
	}
	
	public void setPrettyPrint(boolean prettyPrint) {
		this.prettyPrint = prettyPrint;
	}

}
