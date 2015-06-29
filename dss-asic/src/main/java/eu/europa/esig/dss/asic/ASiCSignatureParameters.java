package eu.europa.esig.dss.asic;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.SignatureLevel;

public class ASiCSignatureParameters extends AbstractSignatureParameters {

	/**
	 * The object representing the parameters related to ASiC from of the signature.
	 */
	private ASiCParameters aSiCParams = new ASiCParameters();

	/**
	 * ds:CanonicalizationMethod indicates the canonicalization algorithm: Algorithm="..." for SignedInfo.
	 */
	private String signedInfoCanonicalizationMethod;

	/**
	 * ds:CanonicalizationMethod indicates the canonicalization algorithm: Algorithm="..." for SignedProperties.
	 */
	private String signedPropertiesCanonicalizationMethod;

	public ASiCParameters aSiC() {
		if (aSiCParams == null) {
			aSiCParams = new ASiCParameters();
		}
		return aSiCParams;
	}

	@Override
	public void setSignatureLevel(SignatureLevel signatureLevel) throws NullPointerException {
		super.setSignatureLevel(signatureLevel);

		ASiCParameters aSiC = aSiC();
		aSiC.containerForm = signatureLevel.getSignatureForm();
	}

	public String getSignedInfoCanonicalizationMethod() {
		return signedInfoCanonicalizationMethod;
	}

	public void setSignedInfoCanonicalizationMethod(String signedInfoCanonicalizationMethod) {
		this.signedInfoCanonicalizationMethod = signedInfoCanonicalizationMethod;
	}

	public String getSignedPropertiesCanonicalizationMethod() {
		return signedPropertiesCanonicalizationMethod;
	}

	public void setSignedPropertiesCanonicalizationMethod(String signedPropertiesCanonicalizationMethod) {
		this.signedPropertiesCanonicalizationMethod = signedPropertiesCanonicalizationMethod;
	}

}
