package eu.europa.esig.dss.spi.exception;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class DSSDataLoaderMultipleException extends DSSExternalResourceException {

	private static final long serialVersionUID = 4981228392826668216L;
	
	private Map<String, Throwable> urlExceptionMap;
	
	public DSSDataLoaderMultipleException(Map<String, Throwable> urlExceptionMap) {
		this.urlExceptionMap = urlExceptionMap;
	}
	
	@Override
	public String getMessage() {
		StringBuilder stringBuilder = new StringBuilder();
		for (Map.Entry<String, Throwable> exceptionEntry : urlExceptionMap.entrySet()) {
			Throwable exception = exceptionEntry.getValue();
			String errorMessage = exception.getMessage();
			if (exception instanceof DSSExternalResourceException) {
				errorMessage = ((DSSExternalResourceException) exception).getCauseMessage();
			}
			stringBuilder.append("Failed to get data from URL '").append(exceptionEntry.getKey()).append("'. Reason : ");
			stringBuilder.append('[').append(errorMessage).append("]. ");
		}
		return stringBuilder.toString();
	}
	
	@Override
	public StackTraceElement[] getStackTrace() {
		List<StackTraceElement> stackTraceElements = new ArrayList<StackTraceElement>();
		for (Throwable exception : urlExceptionMap.values()) {
			stackTraceElements.addAll(Arrays.asList(exception.getStackTrace()));
		}
		return stackTraceElements.toArray(new StackTraceElement[stackTraceElements.size()]);
	}
	
	@Override
	String getCauseMessage() {
		return getMessage();
	}

}
