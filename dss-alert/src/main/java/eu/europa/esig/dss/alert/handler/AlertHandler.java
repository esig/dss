package eu.europa.esig.dss.alert.handler;

/**
 * Executes a process on an object
 *
 * @param <T> a class of the object to execute the alert on
 */
public interface AlertHandler<T> {
	
	/**
	 * Alert user after some change or problem has been detected
	 * 
	 * @param object to execute the alert on
	 */
	void process(T object);

}
