package eu.europa.dss.signature.policy.validation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public abstract class AbstractSignatureAttributesValidator {
	
	private List<String> mandatedAttributes;
	private List<String> missingAttributes = new ArrayList<String>();
	
	public AbstractSignatureAttributesValidator(List<String> mandatedAttributes) {
		super();
		this.mandatedAttributes = mandatedAttributes;
	}

	public boolean validate() {
		if (mandatedAttributes.isEmpty()) {
			return true;
		}
		for (String oid : mandatedAttributes) {
			if (containsAttribute(oid)) {
				missingAttributes.add(oid);
			}
		}
		
		return missingAttributes.isEmpty();
	}

	public List<String> getMissingAttributes() {
		return Collections.unmodifiableList(missingAttributes);
	}

	protected abstract boolean containsAttribute(String oid);
}
