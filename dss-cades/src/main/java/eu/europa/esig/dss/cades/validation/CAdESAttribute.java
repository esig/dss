package eu.europa.esig.dss.cades.validation;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ISignatureAttribute;

public class CAdESAttribute implements ISignatureAttribute {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESAttribute.class);
	
	private final Attribute attribute;
	
	CAdESAttribute(Attribute attribute) {
		this.attribute = attribute;
	}

	/**
	 * Returns object identifier
	 * @return {@link ASN1ObjectIdentifier}
	 */
	public ASN1ObjectIdentifier getASN1Oid() {
		return attribute.getAttrType();
	}
	
	/**
	 * Returns a list of {@link ASN1Primitive} values found in the attribute
	 * @return list of {@link ASN1Primitive}
	 */
	private List<ASN1Primitive> getASN1Primitives() {
		final List<ASN1Primitive> primitives = new ArrayList<ASN1Primitive>();
		final ASN1Set attrValues = attribute.getAttrValues();
		for (final ASN1Encodable value : attrValues.toArray()) {
			if (value instanceof DEROctetString) {
				LOG.warn("Illegal content for timestamp (OID : {}) : OCTET STRING is not allowed !", toString());
			} else {
				primitives.add(value.toASN1Primitive());
			}
		}
		return primitives;
	}
	
	/**
	 * Returns the inner {@link ASN1Primitive} object
	 * @return {@link ASN1Primitive} object
	 */
	public ASN1Primitive getASN1Primitive() {
		List<ASN1Primitive> asn1Primitives = getASN1Primitives();
		if (Utils.isCollectionNotEmpty(asn1Primitives)) {
			if (asn1Primitives.size() > 1) {
				LOG.warn("More than one result in CAdES attribute with OID: [{}]. Return only the first one", toString()); 
			}
			return asn1Primitives.get(0);
		}
		return null;
	}

	/**
	 * Returns the inner {@link ASN1Encodable} object
	 * @return {@link ASN1Sequence} object
	 */
	public ASN1Encodable getASN1Object() {
		return attribute.getAttrValues().getObjectAt(0);
	}
	
	/**
	 * Returns a TimeStampToken if possible
	 * @return {@link TimeStampToken}
	 */
	public TimeStampToken toTimeStampToken() {
		return DSSASN1Utils.getTimeStampToken(attribute);
	}
	
	@Override
	public String toString() {
		ASN1ObjectIdentifier asn1Oid = getASN1Oid();
		if (asn1Oid != null) {
			return asn1Oid.toString();
		}
		return Utils.EMPTY_STRING;
	}

}
