package eu.europa.esig.dss.alert;

import eu.europa.esig.dss.alert.handler.SilentHandler;

public class SilentOnStatusAlert extends AbstractStatusAlert {

	public SilentOnStatusAlert() {
		super(new SilentHandler<>());
	}

}
