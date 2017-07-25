package eu.europa.esig.dss.signature.policy;

import java.util.List;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;

public interface AttributeConstraints {

	List<String> getAttributeTypeConstraints();

	List<AttributeTypeAndValue> getAttributeValueConstraints();

}