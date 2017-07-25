package eu.europa.esig.dss.signature.policy.validation.items;

import java.util.ArrayList;
import java.util.List;

public class CollectionItemValidator implements ItemValidator {

	private List<ItemValidator> items = new ArrayList<>();
	
	@Override
	public boolean validate() {
		boolean validations = true;
		for (ItemValidator itemValidator : items) {
			if (!itemValidator.validate()) {
				validations = false;
			}
		}
		return validations;
	}

	public void add(ItemValidator validator) {
		items.add(validator);
	}
}
