package eu.europa.esig.dss.xades.reference;

import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Node;

import eu.europa.esig.dss.xades.DSSXMLUtils;

/**
 * Transforms a reference content to its base64 representation
 * 
 * NOTE: Not compatible with:
 * - other transformations;
 * - isEmbed(true) parameter;
 * - Manifest signature;
 * - Enveloped signatures.
 */
public class Base64Transform extends AbstractTransform {

	public Base64Transform() {
		super(Transforms.TRANSFORM_BASE64_DECODE);
	}

	@Override
	public byte[] getBytesAfterTranformation(Node node) {
		return DSSXMLUtils.serializeNode(node);
	}

}
