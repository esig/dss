package eu.europa.esig.dss.alert;

/**
 * The interface to handle alert detection and execution
 *
 * @param <T> the object to execute alert detection and handling on
 */
public interface Alert<T> {
	
	/**
	 * Detect and execute the alert on the provided object
	 * 
	 * @param object to detect and, if needed, execute the alert on
	 */
	void alert(T object);

}
