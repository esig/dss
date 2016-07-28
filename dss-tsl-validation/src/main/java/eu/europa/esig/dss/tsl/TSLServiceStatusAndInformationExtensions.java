package eu.europa.esig.dss.tsl;

import java.util.List;

import eu.europa.esig.dss.util.BaseTimeDependent;

public class TSLServiceStatusAndInformationExtensions extends BaseTimeDependent {

	private String status;
	private List<TSLServiceExtension> extensions;

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}
	
	public List<TSLServiceExtension> getExtensions() {
		return extensions;
	}

	public void setExtensions(List<TSLServiceExtension> extensions) {
		this.extensions = extensions;
	}

}
