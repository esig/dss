package eu.europa.esig.dss.xades.reference;

import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Node;

import eu.europa.esig.dss.xades.DSSXMLUtils;

/**
 * Used for Enveloped Signature
 * Note: must be followed up by a {@link CanonicalizationTransform}
 */
public class EnvelopedSignatureTransform extends AbstractTransform {

	public EnvelopedSignatureTransform() {
		super(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
	}

	@Override
	public byte[] getBytesAfterTranformation(Node node) {
		// do nothing the new signature is not existing yet
		// TODO: can be improved (e.g. extended from {@link ComplexTransform})
		return DSSXMLUtils.serializeNode(node);
	}

}
