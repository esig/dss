package port.org.bouncycastle.asn1;

public class ASN1ParsingException extends IllegalStateException {

	private Throwable cause;

	public ASN1ParsingException(String message) {
		super(message);
	}

	public ASN1ParsingException(String message, Throwable cause) {
		super(message);
		this.cause = cause;
	}

	@Override
	public Throwable getCause() {
		return cause;
	}

}
