package eu.europa.esig.dss.tsl.predicates.othertslpointer;

public final class XMLOtherTSLPointer extends MimetypeOtherTSLPointer {

	public static final String EXPECTED_MIMETYPE = "application/vnd.etsi.tsl+xml";

	public XMLOtherTSLPointer() {
		super(EXPECTED_MIMETYPE);
	}

}
