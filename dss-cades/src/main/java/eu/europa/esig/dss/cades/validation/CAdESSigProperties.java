package eu.europa.esig.dss.cades.validation;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;

import eu.europa.esig.dss.validation.timestamp.SignatureProperties;

public abstract class CAdESSigProperties implements SignatureProperties<CAdESAttribute> {
	
	private final AttributeTable attributeTable;
	
	CAdESSigProperties(AttributeTable attributeTable) {
		this.attributeTable = attributeTable;
	}

	@Override
	public boolean isExist() {
		return attributeTable != null;
	}

	@Override
	public List<CAdESAttribute> getAttributes() {
		ASN1EncodableVector asn1EncodableVector = attributeTable.toASN1EncodableVector();
		List<CAdESAttribute> attributes = new ArrayList<CAdESAttribute>();
		for (int ii = 0; ii < asn1EncodableVector.size(); ii++) {
			Attribute attribute = (Attribute) asn1EncodableVector.get(ii);
			attributes.add(new CAdESAttribute(attribute));
		}
		return attributes;
	}

}
