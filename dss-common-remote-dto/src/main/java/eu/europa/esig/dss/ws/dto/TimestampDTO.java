package eu.europa.esig.dss.ws.dto;

import java.util.List;

import eu.europa.esig.dss.enumerations.TimestampType;

public class TimestampDTO {

	private byte[] binaries;
	private String canonicalizationMethod;
	private TimestampType type;
	private List<TimestampIncludeDTO> includes;
	
	public TimestampDTO() {
	}
	
	public TimestampDTO(final byte[] binaries, final TimestampType type) {
		this.binaries = binaries;
		this.type = type;
	}

	public byte[] getBinaries() {
		return binaries;
	}
	
	public void setBinaries(byte[] binaries) {
		this.binaries = binaries;
	}

	public String getCanonicalizationMethod() {
		return canonicalizationMethod;
	}

	public void setCanonicalizationMethod(String canonicalizationMethod) {
		this.canonicalizationMethod = canonicalizationMethod;
	}

	public TimestampType getType() {
		return type;
	}
	
	public void setType(TimestampType type) {
		this.type = type;
	}
	
	public List<TimestampIncludeDTO> getIncludes() {
		return includes;
	}
	
	public void setIncludes(List<TimestampIncludeDTO> includes) {
		this.includes = includes;
	}
	
}
