package eu.europa.esig.dss.alert.detector;

/**
 * The interface used to detect on object if the alert must be executed
 *
 * @param <T> the object to check if the alert must be executed
 */
public interface AlertDetector<T> {

	/**
	 * Detect if an alert must be executed
	 * 
	 * @param object to execute detection on
	 * @return TRUE if the alert must be executed, FALSE otherwise
	 */
	boolean detect(T object);

}
