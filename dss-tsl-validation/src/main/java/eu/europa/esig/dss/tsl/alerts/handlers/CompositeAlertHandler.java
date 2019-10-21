package eu.europa.esig.dss.tsl.alerts.handlers;

import java.util.List;

public class CompositeAlertHandler<T> implements AlertHandler<T> {

	private final List<AlertHandler<T>> handlers;

	public CompositeAlertHandler(List<AlertHandler<T>> handlers) {
		this.handlers = handlers;
	}

	@Override
	public void alert(T currentInfo) {
		for (AlertHandler<T> alertHandler : handlers) {
			alertHandler.alert(currentInfo);
		}
	}

}
