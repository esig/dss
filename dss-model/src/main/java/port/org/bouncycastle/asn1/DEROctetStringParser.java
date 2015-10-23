package port.org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

public class DEROctetStringParser implements ASN1OctetStringParser {

	private DefiniteLengthInputStream stream;

	DEROctetStringParser(DefiniteLengthInputStream stream) {
		this.stream = stream;
	}

	@Override
	public InputStream getOctetStream() {
		return stream;
	}

	@Override
	public ASN1Primitive getLoadedObject() throws IOException {
		return new DEROctetString(stream.toByteArray());
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		try {
			return getLoadedObject();
		} catch (IOException e) {
			throw new ASN1ParsingException("IOException converting stream to byte array: " + e.getMessage(), e);
		}
	}

}
