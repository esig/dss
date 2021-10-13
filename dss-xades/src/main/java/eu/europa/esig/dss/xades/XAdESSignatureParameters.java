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

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.definition.XAdESNamespaces;
import eu.europa.esig.dss.xades.reference.Base64Transform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import org.w3c.dom.Document;

import javax.security.auth.x500.X500Principal;
import java.security.Principal;
import java.security.cert.X509Certificate;
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
	 * Enumeration defining how set value of X509SubjectName
	 */
	public enum X509SubjectNameFormat {

		/**
		 * RFC 1779 String format
		 */
		RFC2253 {
			@Override
			public String getValue(X500Principal x500Principal) {
				return x500Principal.getName(X500Principal.RFC2253);
			}
		},
		/**
		 * RFC 1779 String format
		 */
		RFC1779 {
			@Override
			public String getValue(X500Principal x500Principal) {
				return x500Principal.getName(X500Principal.RFC1779);
			}
		},
		/**
		 * Canonical String format
		 */
		CANONICAL {
			@Override
			public String getValue(X500Principal x500Principal) {
				return x500Principal.getName(X500Principal.CANONICAL);
			}
		};

		/**
		 * Return X509SubjectName of certificate
		 * @param x500Principal certificate
		 * @return name value
		 */
		public abstract String getValue(X500Principal x500Principal);
	}

	/**
	 * The internal signature processing variable
	 */
	private ProfileParameters context;

	/**
	 * This parameter allows to add optional X509SubjectName in the tag X509Data
	 */
	private boolean addX509SubjectName;

	/**
	 * In case of addX509SubjectName is true, this parameter allows choose the format value
	 */
	private X509SubjectNameFormat x509SubjectNameFormat = X509SubjectNameFormat.RFC2253;

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
	 * Defines if the signature shall be creates according to ETSI EN 319 132
	 *
	 * Default: true
	 */
	private boolean en319132 = true;

	/**
	 * ds:CanonicalizationMethod indicates the canonicalization algorithm: Algorithm="..." for KeyInfo.
	 * The EXCLUSIVE canonicalization is used by default
	 */
	private String keyInfoCanonicalizationMethod = DSSXMLUtils.DEFAULT_DSS_C14N_METHOD;

	/**
	 * ds:CanonicalizationMethod indicates the canonicalization algorithm: Algorithm="..." for SignedInfo.
	 * The EXCLUSIVE canonicalization is used by default
	 */
	private String signedInfoCanonicalizationMethod = DSSXMLUtils.DEFAULT_DSS_C14N_METHOD;

	/**
	 * ds:CanonicalizationMethod indicates the canonicalization algorithm: Algorithm="..." for SignedProperties.
	 * The EXCLUSIVE canonicalization is used by default
	 */
	private String signedPropertiesCanonicalizationMethod = DSSXMLUtils.DEFAULT_DSS_C14N_METHOD;

	/**
	 * This parameter allows to produce Manifest signature (https://www.w3.org/TR/xmldsig-core/#sec-o-Manifest).
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
	private DSSNamespace xmldsigNamespace = XAdESNamespaces.XMLDSIG;
	
	/**
	 * XAdES 1.1.1, 1.2.2 or 1.3.2 definition
	 */
	private DSSNamespace xadesNamespace = new DSSNamespace(XAdESNamespaces.XADES_132.getUri(), "xades");

	/**
	 * XAdES 1.4.1 definition
	 */
	private DSSNamespace xades141Namespace = XAdESNamespaces.XADES_141;

	/**
	 * List of custom ds:Object elements to be incorporated inside the signature
	 */
	private List<DSSObject> objects;
	
	/**
	 * The {@code DigestAlgorithm} used to incorporate CompleteCertificateRefs/CompleteRevocationRefs on -C level
	 *
	 * Default: SHA256
	 */
	private DigestAlgorithm tokenReferencesDigestAlgorithm = DigestAlgorithm.SHA256;

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
		if (Utils.isStringEmpty(signedInfoCanonicalizationMethod)) {
			throw new IllegalArgumentException("Canonicalization cannot be empty! See EN 319 132-1: 3.1.2 Signature Generation.");
		}
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
		if (Utils.isStringEmpty(signedPropertiesCanonicalizationMethod)) {
			throw new IllegalArgumentException("Canonicalization cannot be empty! See EN 319 132-1: 3.1.2 Signature Generation.");
		}
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
		if (Utils.isStringEmpty(keyInfoCanonicalizationMethod)) {
			throw new IllegalArgumentException("Canonicalization cannot be empty! See EN 319 132-1: 3.1.2 Signature Generation.");
		}
		this.keyInfoCanonicalizationMethod = keyInfoCanonicalizationMethod;
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
		return dssReferences;
	}

	/**
	 * Sets a list of references to be incorporated into the signature
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
	 * Gets the signature creation context (internal variable)
	 *
	 * @return {@link ProfileParameters}
	 */
	public ProfileParameters getContext() {
		if (context == null) {
			context = new ProfileParameters();
		}
		return context;
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
	 *
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
	 *
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
	 * @return TRUE if teh signature signs a manifest, FALSE otherwise
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
	 *
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
	 *
	 * Default: false
	 *
	 * @param prettyPrint TRUE if to pretty-print the signature, FALSE otherwise
	 */
	public void setPrettyPrint(boolean prettyPrint) {
		this.prettyPrint = prettyPrint;
	}

	/**
	 * Gets format of X509SubjectName value
	 *
	 * @return {@link X509SubjectNameFormat}
	 */
	public X509SubjectNameFormat getX509SubjectNameFormat() {
		return x509SubjectNameFormat;
	}

	/**
	 * Sets format of X509SubjectName value
	 *
	 * Default: RFC2253
	 *
	 * @param x509SubjectNameFormat Format to X509SubjectName value
	 */
	public void setX509SubjectNameFormat(X509SubjectNameFormat x509SubjectNameFormat) {
		this.x509SubjectNameFormat = x509SubjectNameFormat;
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
	 *
	 * Default: ds:http://www.w3.org/2000/09/xmldsig#
	 *
	 * @param xmldsigNamespace {@link DSSNamespace}
	 */
	public void setXmldsigNamespace(DSSNamespace xmldsigNamespace) {
		Objects.requireNonNull(xmldsigNamespace);
		String uri = xmldsigNamespace.getUri();
		if (XAdESNamespaces.XMLDSIG.isSameUri(uri)) {
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
	 *
	 * Default: xades:http://uri.etsi.org/01903/v1.3.2#
	 *
	 * @param xadesNamespace {@link DSSNamespace}
	 */
	public void setXadesNamespace(DSSNamespace xadesNamespace) {
		Objects.requireNonNull(xadesNamespace);
		String uri = xadesNamespace.getUri();
		if (XAdESNamespaces.XADES_111.isSameUri(uri) || XAdESNamespaces.XADES_122.isSameUri(uri) || XAdESNamespaces.XADES_132.isSameUri(uri)) {
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
	 *
	 * Default: xades141:http://uri.etsi.org/01903/v1.4.1#
	 *
	 * @param xades141Namespace {@link DSSNamespace}
	 */
	public void setXades141Namespace(DSSNamespace xades141Namespace) {
		Objects.requireNonNull(xades141Namespace);
		String uri = xades141Namespace.getUri();
		if (XAdESNamespaces.XADES_141.isSameUri(uri)) {
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
	 *
	 * Default : SHA256
	 *
	 * @param tokenReferencesDigestAlgorithm {@link DigestAlgorithm}
	 */
	public void setTokenReferencesDigestAlgorithm(DigestAlgorithm tokenReferencesDigestAlgorithm) {
		this.tokenReferencesDigestAlgorithm = tokenReferencesDigestAlgorithm;
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
	
}
