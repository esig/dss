package eu.europa.esig.dss.asic;

import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class ASiCWithXAdESSignatureParameters extends XAdESSignatureParameters {

	private static final long serialVersionUID = 5004478692506008320L;

	/**
	 * The object representing the parameters related to ASiC from of the signature.
	 */
	private ASiCParameters aSiCParams = new ASiCParameters();

	public ASiCParameters aSiC() {
		return aSiCParams;
	}

	@Override
	public void setSignatureLevel(SignatureLevel signatureLevel) {
		if (signatureLevel == null || SignatureForm.XAdES != signatureLevel.getSignatureForm()) {
			throw new IllegalArgumentException("Only XAdES form is allowed !");
		}
		super.setSignatureLevel(signatureLevel);
	}

}
