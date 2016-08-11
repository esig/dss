package eu.europa.esig.dss.validation.process.bbb;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public abstract class AbstractMultiValuesCheckItem<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	private static final String ALL_VALUE = "*";

	private final MultiValuesConstraint constraint;

	protected AbstractMultiValuesCheckItem(T result, MultiValuesConstraint constraint) {
		super(result, constraint);

		this.constraint = constraint;
	}

	protected boolean processValueCheck(String value) {
		List<String> expecteds = constraint.getId();
		if (Utils.isStringNotEmpty(value) && Utils.isCollectionNotEmpty(expecteds)) {
			if (expecteds.contains(ALL_VALUE)) {
				return true;
			} else if (expecteds.contains(value)) {
				return true;
			}
		}
		return false;
	}

	protected boolean processValuesCheck(List<String> values) {
		if (Utils.isCollectionNotEmpty(values)) {
			if (Utils.isCollectionNotEmpty(constraint.getId())) {
				for (String value : values) {
					for (String expected : constraint.getId()) {
						if (expected.equals(value)) {
							return true;
						}
					}
				}
			}
		}
		return false;
	}

}
