package eu.europa.esig.dss.model;

@SuppressWarnings("serial")
public final class EmptyInMemoryDocument extends InMemoryDocument {

	public static final byte[] EMPTY_BYTE_ARRAY = new byte[0];
	
	public EmptyInMemoryDocument() {
		super(EMPTY_BYTE_ARRAY);
	}

}
