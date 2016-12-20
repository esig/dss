package eu.europa.esig.dss.xades;

import java.util.List;

import org.w3c.dom.Document;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;

public class XAdESSignatureParameters extends AbstractSignatureParameters {

	ProfileParameters context;

	/**
	 * The digest method used to create the digest of the signer's certificate.
	 */
	private DigestAlgorithm signingCertificateDigestMethod = DigestAlgorithm.SHA1;

	/**
	 * ds:CanonicalizationMethod indicates the canonicalization algorithm: Algorithm="..." for SignedInfo.
	 */
	private String signedInfoCanonicalizationMethod;

	/**
	 * ds:CanonicalizationMethod indicates the canonicalization algorithm: Algorithm="..." for SignedProperties.
	 */
	private String signedPropertiesCanonicalizationMethod;

	private List<DSSReference> dssReferences;

	private String xPathLocationString;

	private boolean en319132 = true;

	/**
	 * This attribute is used to inject ASiC root (inclusive canonicalization)
	 */
	private Document rootDocument;

	private boolean embedXML;

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
	 * See {@link #setSigningCertificateDigestMethod(DigestAlgorithm).
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

}
