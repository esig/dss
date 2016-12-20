package eu.europa.esig.dss;

public enum ASiCContainerType {

	/* Associated Signature Container Simple */
	ASiC_S,

	/* Associated Signature Container Extended */
	ASiC_E;

	public String getReadable() {
		String name = this.name();
		return name.replace('_', '-');
	}

}
