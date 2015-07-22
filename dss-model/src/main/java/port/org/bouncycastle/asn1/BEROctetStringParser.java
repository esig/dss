package port.org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

import port.org.bouncycastle.util.io.Streams;

public class BEROctetStringParser implements ASN1OctetStringParser {
	private ASN1StreamParser _parser;

	BEROctetStringParser(ASN1StreamParser parser) {
		_parser = parser;
	}

	@Override
	public InputStream getOctetStream() {
		return new ConstructedOctetStream(_parser);
	}

	@Override
	public ASN1Primitive getLoadedObject() throws IOException {
		return new BEROctetString(Streams.readAll(getOctetStream()));
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
