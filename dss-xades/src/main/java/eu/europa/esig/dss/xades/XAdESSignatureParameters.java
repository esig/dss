/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.dataobject.DSSDataObjectFormat;
import eu.europa.esig.dss.xades.reference.Base64Transform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;
import eu.europa.esig.dss.xades.definition.XAdESNamespace;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigNamespace;
import org.w3c.dom.Document;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Defines SignatureParameters to deal with XAdES signature creation/extension
 */
public class XAdESSignatureParameters extends AbstractSignatureParameters<XAdESTimestampParameters> {

	private static final long serialVersionUID = 9131889715562901184L;

	/**
	 * Enumeration defining ways to embed a signature
	 */
	public enum XPathElementPlacement {

		/**
		 * Insert signature after the element referenced by XPath
		 */
		XPathAfter,
		/**
		 * Insert signature as first child of element referenced by XPath
		 */
		XPathFirstChildOf,
	}

	/**
	 * This parameter allows adding an optional X509SubjectName in the tag X509Data
	 */
	private boolean addX509SubjectName;

	/**
	 * A list of references to incorporate
	 */
	private List<DSSReference> dssReferences;

	/**
	 * In case of ENVELOPING signature, this parameter allows to include the complete XML and not its base64 encoded
	 * value
	 * NOTE: not compatible with {@link Base64Transform}
	 */
	private boolean embedXML;

	/**
	 * Defines if the signature shall be created according to ETSI EN 319 132
	 * Default: true
	 */
	private boolean en319132 = true;

	/**
	 * ds:CanonicalizationMethod indicates the canonicalization algorithm: Algorithm="..." for KeyInfo.
	 * The EXCLUSIVE canonicalization is used by default
	 */
	private String keyInfoCanonicalizationMethod = XMLCanonicalizer.DEFAULT_DSS_C14N_METHOD;

	/**
	 * ds:CanonicalizationMethod indicates the canonicalization algorithm: Algorithm="..." for SignedInfo.
	 * The EXCLUSIVE canonicalization is used by default
	 */
	private String signedInfoCanonicalizationMethod = XMLCanonicalizer.DEFAULT_DSS_C14N_METHOD;

	/**
	 * ds:CanonicalizationMethod indicates the canonicalization algorithm: Algorithm="..." for SignedProperties.
	 * The EXCLUSIVE canonicalization is used by default
	 */
	private String signedPropertiesCanonicalizationMethod = XMLCanonicalizer.DEFAULT_DSS_C14N_METHOD;

	/**
	 * This parameter allows producing a Manifest signature (https://www.w3.org/TR/xmldsig-core/#sec-o-Manifest).
	 */
	private boolean manifestSignature;

	/**
	 * This attribute defines the root element of the file to create signature in (used in INTERNALLY_DETACHED)
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
	 * Optional parameter defining should the "KeyInfo" element be signed.
	 * If the value of parameter is TRUE, reference of the "KeyInfo" element will be added to "SignedInfo".
	 * FALSE by default.
	 */
	private boolean signKeyInfo = false;

	/**
	 * Defines the signature position xpath string (used for ENVELOPED format)
	 */
	private String xPathLocationString;

	/**
	 * Defines the signature placement relatively to the element defined
	 * in the {@code xPathLocationString} (used for ENVELOPED format)
	 */
	private XPathElementPlacement xPathElementPlacement;
	
	/**
	 * If true, prints each signature's tag to a new line with a relevant indent
	 */
	private boolean prettyPrint = false;

	/**
	 * XMLDSig definition
	 */
	private DSSNamespace xmldsigNamespace = XMLDSigNamespace.NS;
	
	/**
	 * XAdES 1.1.1, 1.2.2 or 1.3.2 definition
	 */
	private DSSNamespace xadesNamespace = new DSSNamespace(XAdESNamespace.XADES_132.getUri(), "xades");

	/**
	 * XAdES 1.4.1 definition
	 */
	private DSSNamespace xades141Namespace = XAdESNamespace.XADES_141;

	/**
	 * List of custom ds:Object elements to be incorporated inside the signature
	 */
	private List<DSSObject> objects;
	
	/**
	 * The {@code DigestAlgorithm} used to incorporate CompleteCertificateRefs/CompleteRevocationRefs on -C level
	 * Default: SHA512
	 */
	private DigestAlgorithm tokenReferencesDigestAlgorithm = DigestAlgorithm.SHA512;

	/**
	 * List of custom xades:DataObjectFormat elements incorporated within xades:SignedDataObjectProperties element of the signature
	 */
	private List<DSSDataObjectFormat> dataObjectFormatList;

	/**
	 * Default constructor instantiating object with null values
	 */
	public XAdESSignatureParameters() {
		// empty
	}

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
	 * Default: SHA512 (DigestAlgorithm.SHA512)
	 *
	 * @param signingCertificateDigestMethod {@link DigestAlgorithm}
	 */
	public void setSigningCertificateDigestMethod(final DigestAlgorithm signingCertificateDigestMethod) {
		Objects.requireNonNull(signingCertificateDigestMethod, "SigningCertificateDigestMethod cannot be null!");
		this.signingCertificateDigestMethod = signingCertificateDigestMethod;
	}

	/**
	 * See {@link #setSigningCertificateDigestMethod(DigestAlgorithm)}.
	 *
	 * @return {@link DigestAlgorithm}
	 */
	public DigestAlgorithm getSigningCertificateDigestMethod() {
		return signingCertificateDigestMethod;
	}

	/**
	 * Gets the SignedInfo canonicalization algorithm
	 *
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
		assertCanonicalizationNotEmpty(signedInfoCanonicalizationMethod);
		this.signedInfoCanonicalizationMethod = signedInfoCanonicalizationMethod;
	}

	/**
	 * Gets the SignedProperties canonicalization algorithm
	 *
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
		assertCanonicalizationNotEmpty(signedPropertiesCanonicalizationMethod);
		this.signedPropertiesCanonicalizationMethod = signedPropertiesCanonicalizationMethod;
	}
	
	/**
	 * Returns the canonicalization algorithm used for dealing with KeyInfo
	 *
	 * @return - name of the canonicalization algorithm
	 */
	public String getKeyInfoCanonicalizationMethod() {
		return keyInfoCanonicalizationMethod;
	}
	
	/**
	 * Set the canonicalization algorithm used for dealing with KeyInfo.
	 *
	 * @param keyInfoCanonicalizationMethod - name of the canonicalization algorithm for dealing with KeyInfo.
	 */
	public void setKeyInfoCanonicalizationMethod(final String keyInfoCanonicalizationMethod) {
		assertCanonicalizationNotEmpty(keyInfoCanonicalizationMethod);
		this.keyInfoCanonicalizationMethod = keyInfoCanonicalizationMethod;
	}

	private static void assertCanonicalizationNotEmpty(String canonicalizationMethod) {
		if (Utils.isStringEmpty(canonicalizationMethod)) {
			throw new IllegalArgumentException("Canonicalization cannot be empty! See EN 319 132-1: 3.1.2 Signature Generation.");
		}
	}
	
	/**
	 * Returns value value specifying if "KeyInfo" element should be signed.
	 *
	 * @return TRUE if "KeyInfo" element must be signed, FALSE otherwise.
	 */
	public boolean isSignKeyInfo() {
		return signKeyInfo;
	}
	
	/**
	 * Set the parameter SignKeyInfo defining if the "KeyInfo" element must be signed and
	 * 		its reference must be included to "SignedInfo" element.
	 * 		The value is FALSE by default.
	 *
	 * @param signKeyInfo - if KeyInfo element should be signed
	 */
	public void setSignKeyInfo(boolean signKeyInfo) {
		this.signKeyInfo = signKeyInfo;
	}

	/**
	 * Returns a list of references to be incorporated to the signature
	 *
	 * @return a list of {@link DSSReference}s
	 */
	public List<DSSReference> getReferences() {
		if (Utils.isCollectionNotEmpty(dssReferences)) {
			return dssReferences;
		}
		XAdESProfileParameters context = getContext();
		if (context != null) {
			return context.getReferences();
		}
		return null;
	}

	/**
	 * Sets a list of references to be incorporated into the signature
	 * NOTE: This method overwrites a default behavior on ds:Reference's creation. It should be used only by experienced users.
	 *
	 * @param references a list of {@link DSSReference}s
	 */
	public void setReferences(List<DSSReference> references) {
		this.dssReferences = references;
	}

	/**
	 * Gets the xPath signature location string (ENVELOPED only)
	 *
	 * @return {@link String} xPath
	 */
	public String getXPathLocationString() {
		return xPathLocationString;
	}

	/**
	 * Defines the position where the signature will be added (XAdES Enveloped)
	 * 
	 * @param xPathLocationString
	 *            the xpath position of the signature
	 */
	public void setXPathLocationString(String xPathLocationString) {
		this.xPathLocationString = xPathLocationString;
	}

	/**
	 * Returns the XPath element placement for Enveloped signature creation
	 *
	 * @return {@link XPathElementPlacement}
	 */
	public XPathElementPlacement getXPathElementPlacement() {
        return xPathElementPlacement;
    }

	/**
	 * Defines the relation to the element referenced by the XPath where the signature will be added (XAdES Enveloped)
	 *
	 * @param xPathElementPlacement
	 *            the placement of the signature
	 */
    public void setXPathElementPlacement(XPathElementPlacement xPathElementPlacement) {
        this.xPathElementPlacement = xPathElementPlacement;
    }

	/**
	 * Returns the root document for INTERNALLY_DETACHED signature creation
	 *
	 * @return {@link Document}
	 */
	public Document getRootDocument() {
		return rootDocument;
	}

	/**
	 * Sets the root document for INTERNALLY_DETACHED signature creation
	 *
	 * @param rootDocument {@link Document}
	 */
	public void setRootDocument(Document rootDocument) {
		this.rootDocument = rootDocument;
	}

	/**
	 * Sets the root XML document for a signature creation.
	 * This method expected a {@code rootDocument} to be represented by a valid XML document
	 *
	 * @param rootDocument {@link DSSDocument} represented by an XML document
	 */
	public void setRootDocument(DSSDocument rootDocument) {
		if (rootDocument == null) {
			setRootDocument((Document) null);
		}
		if (!DomUtils.isDOM(rootDocument)) {
			throw new IllegalArgumentException("The rootDocument shall be represented by a valid XML document!");
		}
		setRootDocument(DomUtils.buildDOM(rootDocument));
	}

	/**
	 * Gets the signature creation context (internal variable)
	 *
	 * @return {@link XAdESProfileParameters}
	 */
	@Override
	public XAdESProfileParameters getContext() {
		if (context == null) {
			context = new XAdESProfileParameters();
		}
		return (XAdESProfileParameters) context;
	}

	/**
	 * Gets if the signature shall be created according to ETSI EN 319 132
	 *
	 * @return TRUE if the signature shall be created according to ETSI EN 319 132,
	 * otherwise according to the old standard
	 */
	public boolean isEn319132() {
		return en319132;
	}

	/**
	 * Sets if the signature shall be created according to ETSI EN 319 132
	 * <p>
	 * Default: true
	 *
	 * @param en319132 if the signature shall be created according to ETSI EN 319 132
	 */
	public void setEn319132(boolean en319132) {
		this.en319132 = en319132;
	}

	/**
	 * Gets if the signed content shall be incorporated as XML (used for ENVELOPING)
	 *
	 * @return TRUE if the signed content shall be incorporated as XML, FALSE otherwise (base64 encoded binaries)
	 */
	public boolean isEmbedXML() {
		return embedXML;
	}

	/**
	 * Sets if the signed content shall be incorporated as XML (used for ENVELOPING)
	 * If false, incorporates the document content in its base64 encoded representation
	 * <p>
	 * Default: false (base64 encoded binaries)
	 *
	 * @param embedXML if the signed content shall be incorporated as XML
	 */
	public void setEmbedXML(boolean embedXML) {
		this.embedXML = embedXML;
	}

	/**
	 * Gets if the signature signs a manifest
	 *
	 * @return TRUE if the signature signs a manifest, FALSE otherwise
	 */
	public boolean isManifestSignature() {
		return manifestSignature;
	}

	/**
	 * Sets if the signature signs a manifest
	 *
	 * @param manifestSignature if the signature signs a manifest
	 */
	public void setManifestSignature(boolean manifestSignature) {
		this.manifestSignature = manifestSignature;
	}

	/**
	 * Gets if the {@code <ds:X509Data>} element shall be added
	 *
	 * @return TRUE if the X509Data element shall be added, FALSE otherwise
	 */
	public boolean isAddX509SubjectName() {
		return addX509SubjectName;
	}

	/**
	 * Sets if the {@code <ds:X509Data>} element shall be added
	 * <p>
	 * Default: false
	 *
	 * @param addX509SubjectName if the X509Data element shall be added
	 */
	public void setAddX509SubjectName(boolean addX509SubjectName) {
		this.addX509SubjectName = addX509SubjectName;
	}

	/**
	 * Gets a custom XAdES Object content
	 *
	 * @return XAdES Object binaries
	 */
	public byte[] getSignedAdESObject() {
		return signedAdESObject;
	}

	/**
	 * Sets a custom XAdES Object content
	 *
	 * @param signedAdESObject XAdES Object content to incorporate into the signature
	 */
	public void setSignedAdESObject(byte[] signedAdESObject) {
		this.signedAdESObject = signedAdESObject;
	}

	/**
	 * Gets if the signature shall be pretty-printed
	 *
	 * @return TRUE if pretty-print the signature, FALSE otherwise
	 */
	public boolean isPrettyPrint() {
		return prettyPrint;
	}

	/**
	 * Sets if the signature shall be pretty-printed
	 * <p>
	 * Default: false
	 *
	 * @param prettyPrint TRUE if to pretty-print the signature, FALSE otherwise
	 */
	public void setPrettyPrint(boolean prettyPrint) {
		this.prettyPrint = prettyPrint;
	}

	/**
	 * This method returns the current used XMLDSig namespace
	 * Never returns null
	 *
	 * @return {@link DSSNamespace}
	 */
	public DSSNamespace getXmldsigNamespace() {
		return xmldsigNamespace;
	}

	/**
	 * Sets the XMLDSIG namespace
	 * <p>
	 * Default: ds:http://www.w3.org/2000/09/xmldsig#
	 *
	 * @param xmldsigNamespace {@link DSSNamespace}
	 */
	public void setXmldsigNamespace(DSSNamespace xmldsigNamespace) {
		Objects.requireNonNull(xmldsigNamespace);
		String uri = xmldsigNamespace.getUri();
		if (XMLDSigNamespace.NS.isSameUri(uri)) {
			this.xmldsigNamespace = xmldsigNamespace;
		} else {
			throw new IllegalArgumentException("Not accepted URI");
		}
	}

	/**
	 * This method returns the current used XAdES namespace
	 * Never returns null
	 *
	 * @return {@link DSSNamespace}
	 */
	public DSSNamespace getXadesNamespace() {
		return xadesNamespace;
	}

	/**
	 * Sets the XAdES namespace
	 * <p>
	 * Default: xades:http://uri.etsi.org/01903/v1.3.2#
	 *
	 * @param xadesNamespace {@link DSSNamespace}
	 */
	public void setXadesNamespace(DSSNamespace xadesNamespace) {
		Objects.requireNonNull(xadesNamespace);
		String uri = xadesNamespace.getUri();
		if (XAdESNamespace.XADES_111.isSameUri(uri) || XAdESNamespace.XADES_122.isSameUri(uri) || XAdESNamespace.XADES_132.isSameUri(uri)) {
			this.xadesNamespace = xadesNamespace;
		} else {
			throw new IllegalArgumentException("Not accepted URI");
		}
	}

	/**
	 * This method returns the current used XAdES 1.4.1 namespace
	 * Never returns null
	 *
	 * @return {@link DSSNamespace}
	 */
	public DSSNamespace getXades141Namespace() {
		return xades141Namespace;
	}

	/**
	 * Sets the XAdES 1.4.1 namespace
	 * <p>
	 * Default: xades141:http://uri.etsi.org/01903/v1.4.1#
	 *
	 * @param xades141Namespace {@link DSSNamespace}
	 */
	public void setXades141Namespace(DSSNamespace xades141Namespace) {
		Objects.requireNonNull(xades141Namespace);
		String uri = xades141Namespace.getUri();
		if (XAdESNamespace.XADES_141.isSameUri(uri)) {
			this.xades141Namespace = xades141Namespace;
		} else {
			throw new IllegalArgumentException("Not accepted URI");
		}
	}

	/**
	 * Gets the list of custom ds:Object elements
	 *
	 * @return a list of {@link DSSObject}s
	 */
	public List<DSSObject> getObjects() {
		return objects;
	}

	/**
	 * Sets the list of custom ds:Object elements to be incorporated within the ds:Signature
	 *
	 * @param objects a list of {@link DSSObject} to be included
	 */
	public void setObjects(List<DSSObject> objects) {
		this.objects = objects;
	}

	/**
	 * Gets a {@code DigestAlgorithm} to create CompleteCertificateRefs/CompleteRevocationRefs with
	 *
	 * @return {@link DigestAlgorithm}
	 */
	public DigestAlgorithm getTokenReferencesDigestAlgorithm() {
		return tokenReferencesDigestAlgorithm;
	}

	/**
	 * Sets a {@code DigestAlgorithm} to create CompleteCertificateRefs/CompleteRevocationRefs for -C level
	 * <p>
	 * Default: SHA512
	 *
	 * @param tokenReferencesDigestAlgorithm {@link DigestAlgorithm}
	 */
	public void setTokenReferencesDigestAlgorithm(DigestAlgorithm tokenReferencesDigestAlgorithm) {
		Objects.requireNonNull(tokenReferencesDigestAlgorithm, "TokenReferencesDigestAlgorithm cannot be null!");
		this.tokenReferencesDigestAlgorithm = tokenReferencesDigestAlgorithm;
	}

	/**
	 * Gets a list of custom xades:DataObjectFormat elements
	 *
	 * @return list of {@link DSSDataObjectFormat}s
	 */
	public List<DSSDataObjectFormat> getDataObjectFormatList() {
		return dataObjectFormatList;
	}

	/**
	 * Sets a list of custom xades:DataObjectFormat elements to be incorporated within
	 * xades:SignedDataObjectProperties element of the signature.
	 * NOTE: this method overwrites default behavior on xades:DataObjectFormat creation. It should be used only by experienced users.
	 *
	 * @param dataObjectFormatList list of {@link DSSDataObjectFormat}s
	 */
	public void setDataObjectFormatList(List<DSSDataObjectFormat> dataObjectFormatList) {
		this.dataObjectFormatList = dataObjectFormatList;
	}

	@Override
	public XAdESTimestampParameters getContentTimestampParameters() {
		if (contentTimestampParameters == null) {
			contentTimestampParameters = new XAdESTimestampParameters();
		}
		return contentTimestampParameters;
	}

	@Override
	public XAdESTimestampParameters getSignatureTimestampParameters() {
		if (signatureTimestampParameters == null) {
			signatureTimestampParameters = new XAdESTimestampParameters();
		}
		return signatureTimestampParameters;
	}

	@Override
	public XAdESTimestampParameters getArchiveTimestampParameters() {
		if (archiveTimestampParameters == null) {
			archiveTimestampParameters = new XAdESTimestampParameters();
		}
		return archiveTimestampParameters;
	}
	
	@Override
	public void reinit() {
		super.reinit();
		context = null;
	}

	@Override
	public String toString() {
		return "XAdESSignatureParameters [" +
				"addX509SubjectName=" + addX509SubjectName +
				", dssReferences=" + dssReferences +
				", embedXML=" + embedXML +
				", en319132=" + en319132 +
				", keyInfoCanonicalizationMethod='" + keyInfoCanonicalizationMethod + '\'' +
				", signedInfoCanonicalizationMethod='" + signedInfoCanonicalizationMethod + '\'' +
				", signedPropertiesCanonicalizationMethod='" + signedPropertiesCanonicalizationMethod + '\'' +
				", manifestSignature=" + manifestSignature +
				", rootDocument=" + rootDocument +
				", signedAdESObject=" + Arrays.toString(signedAdESObject) +
				", signingCertificateDigestMethod=" + signingCertificateDigestMethod +
				", signKeyInfo=" + signKeyInfo +
				", xPathLocationString='" + xPathLocationString + '\'' +
				", xPathElementPlacement=" + xPathElementPlacement +
				", prettyPrint=" + prettyPrint +
				", xmldsigNamespace=" + xmldsigNamespace +
				", xadesNamespace=" + xadesNamespace +
				", xades141Namespace=" + xades141Namespace +
				", objects=" + objects +
				", tokenReferencesDigestAlgorithm=" + tokenReferencesDigestAlgorithm +
				", dataObjectFormatList=" + dataObjectFormatList +
				"] " + super.toString();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		if (!super.equals(o)) return false;

		XAdESSignatureParameters that = (XAdESSignatureParameters) o;
		return addX509SubjectName == that.addX509SubjectName
				&& embedXML == that.embedXML
				&& en319132 == that.en319132
				&& manifestSignature == that.manifestSignature
				&& signKeyInfo == that.signKeyInfo
				&& prettyPrint == that.prettyPrint
				&& Objects.equals(dssReferences, that.dssReferences)
				&& Objects.equals(keyInfoCanonicalizationMethod, that.keyInfoCanonicalizationMethod)
				&& Objects.equals(signedInfoCanonicalizationMethod, that.signedInfoCanonicalizationMethod)
				&& Objects.equals(signedPropertiesCanonicalizationMethod, that.signedPropertiesCanonicalizationMethod)
				&& Objects.equals(rootDocument, that.rootDocument)
				&& Arrays.equals(signedAdESObject, that.signedAdESObject)
				&& signingCertificateDigestMethod == that.signingCertificateDigestMethod
				&& Objects.equals(xPathLocationString, that.xPathLocationString)
				&& xPathElementPlacement == that.xPathElementPlacement
				&& Objects.equals(xmldsigNamespace, that.xmldsigNamespace)
				&& Objects.equals(xadesNamespace, that.xadesNamespace)
				&& Objects.equals(xades141Namespace, that.xades141Namespace)
				&& Objects.equals(objects, that.objects)
				&& tokenReferencesDigestAlgorithm == that.tokenReferencesDigestAlgorithm
				&& Objects.equals(dataObjectFormatList, that.dataObjectFormatList);
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + Boolean.hashCode(addX509SubjectName);
		result = 31 * result + Objects.hashCode(dssReferences);
		result = 31 * result + Boolean.hashCode(embedXML);
		result = 31 * result + Boolean.hashCode(en319132);
		result = 31 * result + Objects.hashCode(keyInfoCanonicalizationMethod);
		result = 31 * result + Objects.hashCode(signedInfoCanonicalizationMethod);
		result = 31 * result + Objects.hashCode(signedPropertiesCanonicalizationMethod);
		result = 31 * result + Boolean.hashCode(manifestSignature);
		result = 31 * result + Objects.hashCode(rootDocument);
		result = 31 * result + Arrays.hashCode(signedAdESObject);
		result = 31 * result + Objects.hashCode(signingCertificateDigestMethod);
		result = 31 * result + Boolean.hashCode(signKeyInfo);
		result = 31 * result + Objects.hashCode(xPathLocationString);
		result = 31 * result + Objects.hashCode(xPathElementPlacement);
		result = 31 * result + Boolean.hashCode(prettyPrint);
		result = 31 * result + Objects.hashCode(xmldsigNamespace);
		result = 31 * result + Objects.hashCode(xadesNamespace);
		result = 31 * result + Objects.hashCode(xades141Namespace);
		result = 31 * result + Objects.hashCode(objects);
		result = 31 * result + Objects.hashCode(tokenReferencesDigestAlgorithm);
		result = 31 * result + Objects.hashCode(dataObjectFormatList);
		return result;
	}

}
