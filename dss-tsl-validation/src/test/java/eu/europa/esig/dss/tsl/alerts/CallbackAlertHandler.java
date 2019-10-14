package eu.europa.esig.dss.tsl.alerts;

import eu.europa.esig.dss.spi.tsl.TLInfo;

class CallbackAlertHandler implements AlertHandler<TLInfo> {
	
	private boolean called = false;

	@Override
	public void alert(TLInfo currentInfo) {
		called = true;
	}

	public boolean isCalled() {
		return called;
	}
	
}
