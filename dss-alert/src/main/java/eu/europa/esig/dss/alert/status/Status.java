package eu.europa.esig.dss.alert.status;

import java.util.Collection;

public class Status {

	private final String message;
	private final Collection<String> relatedObjectIds;

	public Status(String message) {
		this.message = message;
		this.relatedObjectIds = null;
	}

	public Status(String message, Collection<String> relatedObjectIds) {
		this.message = message;
		this.relatedObjectIds = relatedObjectIds;
	}

	public String getMessage() {
		return message;
	}

	public Collection<String> getRelatedObjectIds() {
		return relatedObjectIds;
	}

	public boolean isEmpty() {
		return message == null || message.isEmpty();
	}

	@Override
	public String toString() {
		return message + (relatedObjectIds == null ? "" : " " + relatedObjectIds);
	}

}
