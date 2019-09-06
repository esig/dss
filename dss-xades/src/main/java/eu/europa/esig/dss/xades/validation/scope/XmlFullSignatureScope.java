package eu.europa.esig.dss.xades.validation.scope;

import java.util.List;

import eu.europa.esig.dss.model.Digest;

public final class XmlFullSignatureScope extends XmlRootSignatureScope {

	protected XmlFullSignatureScope(String name, List<String> transformations, Digest digest) {
		super(name, transformations, digest);
	}

}
