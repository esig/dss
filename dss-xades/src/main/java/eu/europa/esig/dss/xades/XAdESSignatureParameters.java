package eu.europa.esig.dss.xades;

import java.util.List;

import org.w3c.dom.Document;

import eu.europa.esig.dss.AbstractSignatureParameters;

public class XAdESSignatureParameters extends AbstractSignatureParameters {

	ProfileParameters context;

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

	private String toCounterSignSignatureId;

	private String toCounterSignSignatureValueId;

	/**
	 *	This attribute is used to inject ASiC root (inclusive canonicalization)
	 */
	private Document rootDocument;


	/**
	 * @return the canonicalization algorithm to be used when dealing with SignedInfo.
	 */
	public String getSignedInfoCanonicalizationMethod() {
		return signedInfoCanonicalizationMethod;
	}

	/**
	 * Set the canonicalization algorithm to be used when dealing with SignedInfo.
	 *
	 * @param signedInfoCanonicalizationMethod the canonicalization algorithm to be used when dealing with SignedInfo.
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
	 * @param signedPropertiesCanonicalizationMethod the canonicalization algorithm to be used when dealing with SignedInfo.
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
	 * @param xPathLocationString the xpath location of the signature
	 */
	public void setXPathLocationString(String xPathLocationString) {
		this.xPathLocationString = xPathLocationString;
	}

	/**
	 * This method returns the Id of the signature to be countersigned.
	 *
	 * @return
	 */
	public String getToCounterSignSignatureId() {
		return toCounterSignSignatureId;
	}

	/**
	 * This method sets the Id of the signature to be countersigned.
	 *
	 * @param toCounterSignSignatureId
	 */
	public void setToCounterSignSignatureId(String toCounterSignSignatureId) {
		this.toCounterSignSignatureId = toCounterSignSignatureId;
	}

	public String getToCounterSignSignatureValueId() {
		return toCounterSignSignatureValueId;
	}

	public void setToCounterSignSignatureValueId(String toCounterSignSignatureValueId) {
		this.toCounterSignSignatureValueId = toCounterSignSignatureValueId;
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
}
