package eu.europa.esig.dss.alert.handler;

import java.util.List;

public class CompositeAlertHandler<T> implements AlertHandler<T> {

	private final List<AlertHandler<T>> handlers;

	public CompositeAlertHandler(List<AlertHandler<T>> handlers) {
		this.handlers = handlers;
	}

	@Override
	public void process(T object) {
		for (AlertHandler<T> alertHandler : handlers) {
			alertHandler.process(object);
		}
	}

}
