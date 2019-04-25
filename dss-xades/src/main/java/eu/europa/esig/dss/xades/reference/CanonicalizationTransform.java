package eu.europa.esig.dss.xades.reference;

import org.w3c.dom.Node;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.xades.DSSXMLUtils;

public class CanonicalizationTransform extends AbstractTransform {

	public CanonicalizationTransform(String canonicalizationAlgorithm) {
		super(canonicalizationAlgorithm);
		if (!DSSXMLUtils.canCanonicalize(canonicalizationAlgorithm)) {
			throw new DSSException(String.format("The provided canonicalization method [%s] is not supported!", canonicalizationAlgorithm));
		}
	}

	@Override
	public byte[] getBytesAfterTranformation(Node node) {
		return DSSXMLUtils.canonicalizeSubtree(algorithm, node);
	}

}
