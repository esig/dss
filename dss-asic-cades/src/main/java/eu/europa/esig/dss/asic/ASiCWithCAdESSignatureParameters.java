package eu.europa.esig.dss.asic;

import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;

public class ASiCWithCAdESSignatureParameters extends CAdESSignatureParameters {

	private static final long serialVersionUID = -830012801924753709L;

	/**
	 * The object representing the parameters related to ASiC from of the signature.
	 */
	private ASiCParameters aSiCParams = new ASiCParameters();

	public ASiCParameters aSiC() {
		return aSiCParams;
	}

	@Override
	public void setSignatureLevel(SignatureLevel signatureLevel) {
		if (signatureLevel == null || SignatureForm.CAdES != signatureLevel.getSignatureForm()) {
			throw new IllegalArgumentException("Only CAdES form is allowed !");
		}
		super.setSignatureLevel(signatureLevel);
	}

}
