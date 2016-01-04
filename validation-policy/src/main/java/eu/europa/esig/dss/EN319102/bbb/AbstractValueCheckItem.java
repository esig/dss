package eu.europa.esig.dss.EN319102.bbb;

import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public abstract class AbstractValueCheckItem<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	private static final String ALL_VALUE = "*";

	protected AbstractValueCheckItem(T result, LevelConstraint constraint) {
		super(result, constraint);
	}

	protected boolean processValueCheck(String value, String expected) {
		if (StringUtils.isEmpty(value)) {
			return false;
		}

		if (ALL_VALUE.equals(expected)) {
			return true;
		} else {
			return StringUtils.equals(expected, value);
		}
	}

}
