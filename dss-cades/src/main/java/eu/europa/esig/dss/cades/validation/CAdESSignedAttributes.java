package eu.europa.esig.dss.cades.validation;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.SignerInformation;

public class CAdESSignedAttributes extends CAdESSigProperties {
	
	public CAdESSignedAttributes() {
		super(null);
	}

	CAdESSignedAttributes(AttributeTable attributeTable) {
		super(attributeTable);
	}
	
	public static CAdESSignedAttributes build(SignerInformation signerInformation) {
		return new CAdESSignedAttributes(signerInformation.getSignedAttributes());
	}

}
