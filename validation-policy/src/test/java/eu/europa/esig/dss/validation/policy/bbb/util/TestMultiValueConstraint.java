package eu.europa.esig.dss.validation.policy.bbb.util;

import java.util.ArrayList;

import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class TestMultiValueConstraint extends MultiValuesConstraint {

	
	public void addConstraint(String constraint) {
		if(id == null) {
			id = new ArrayList<String>();
		}
		id.add(constraint);
	}
}
