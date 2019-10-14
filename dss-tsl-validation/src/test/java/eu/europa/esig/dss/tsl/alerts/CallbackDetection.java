package eu.europa.esig.dss.tsl.alerts;

import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.tsl.alerts.detections.AbstractTLDetection;

class CallbackDetection extends AbstractTLDetection {
	
	private boolean called = false;
	
	private boolean countryChecked = false;

	private String tlCountry;
	
	public void setTlCountry(String tlCountry) {
		this.tlCountry = tlCountry;
	}
	
	@Override
	public boolean detect(TLInfo info) {
		called = true;
		if(tlCountry != null) {
			countryChecked = true;
		}
		return false;
	}

	public boolean isCalled() {
		return called;
	}

	public void setCalled(boolean called) {
		this.called = called;
	}

	public boolean isCountryChecked() {
		return countryChecked;
	}

	public void setCountryChecked(boolean countryChecked) {
		this.countryChecked = countryChecked;
	}

}
