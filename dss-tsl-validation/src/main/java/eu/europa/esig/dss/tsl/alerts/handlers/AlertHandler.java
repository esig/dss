package eu.europa.esig.dss.tsl.alerts.handlers;

public interface AlertHandler<T> {
	
	/**
	 * Alert user after some change or problem has been detected
	 * 
	 * @param currentInfo the current LOTLInformation or TLInformation that caused the alert
	 */
	void alert(T currentInfo);
		
}
