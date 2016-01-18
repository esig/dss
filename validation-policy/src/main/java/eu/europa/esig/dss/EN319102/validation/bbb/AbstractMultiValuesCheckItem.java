package eu.europa.esig.dss.EN319102.validation.bbb;

import java.util.List;

import org.apache.commons.collections.CollectionUtils;

import eu.europa.esig.dss.EN319102.validation.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public abstract class AbstractMultiValuesCheckItem<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	protected AbstractMultiValuesCheckItem(T result, MultiValuesConstraint constraint) {
		super(result, constraint);
	}

	protected boolean processValuesCheck(List<String> values, List<String> expecteds) {
		if (CollectionUtils.isNotEmpty(values)) {
			if (CollectionUtils.isNotEmpty(expecteds)) {
				for (String value : values) {
					for (String expected : expecteds) {
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
