package eu.europa.esig.dss.enumerations;

public enum TimestampContainerForm {
	
	/* Used to timestamp a PDF document */
	PDF,
	
	/* Used to timestamp provided document(s) and creates an ASiC-E container */
	ASiC_E,
	
	/* Used to timestamp provided document(s) and creates an ASiC-S container */
	ASiC_S;

	public String getReadable() {
		String name = this.name();
		return name.replace('_', '-');
	}

}
