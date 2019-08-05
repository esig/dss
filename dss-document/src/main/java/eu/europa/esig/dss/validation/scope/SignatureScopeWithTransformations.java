package eu.europa.esig.dss.validation.scope;

import java.util.List;

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.utils.Utils;

public abstract class SignatureScopeWithTransformations extends SignatureScope {

	private final List<String> transformations;

	protected SignatureScopeWithTransformations(final String name, final Digest digest, final List<String> transformations) {
		super(name, digest);
		this.transformations = transformations;
	}
	
	protected String addTransformationDescription(String description) {
		description += " with transformations.";
		return description;
	}
	
	protected boolean isTransformationsNotEmpty() {
		return Utils.isCollectionNotEmpty(transformations);
	}

	@Override
	public List<String> getTransformations() {
		return transformations;
	}

}
