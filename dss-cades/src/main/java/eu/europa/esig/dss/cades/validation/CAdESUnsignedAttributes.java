package eu.europa.esig.dss.cades.validation;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.SignerInformation;

public class CAdESUnsignedAttributes extends CAdESSigProperties {

	CAdESUnsignedAttributes(AttributeTable attributeTable) {
		super(attributeTable);
	}
	
	public static CAdESUnsignedAttributes build(SignerInformation signerInformation) {
		return new CAdESUnsignedAttributes(signerInformation.getUnsignedAttributes());
	}

}