package eu.europa.esig.dss.tsl.alerts.detections;

public interface Detection<T> {

	/**
	 * Detect if there is any change or problem with a specific LOTL or TL
	 * 
	 * @param info the current LOTLInformation or TLInformation to be checked for changes/problems
	 * @return true if the current change/problem to be checked is found and false otherwise
	 */
	boolean detect(T info);

}
