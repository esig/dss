package eu.europa.esig.dss.alert.handler;

/**
 * Implementation of {@code AlertHandler} which does nothing
 */
public class SilentHandler<T> implements AlertHandler<T> {

	@Override
	public void process(T object) {
		// do nothing
	}

}
