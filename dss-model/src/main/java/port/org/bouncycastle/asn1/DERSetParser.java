package port.org.bouncycastle.asn1;

import java.io.IOException;

public class DERSetParser implements ASN1SetParser {

	private ASN1StreamParser _parser;

	DERSetParser(ASN1StreamParser parser) {
		this._parser = parser;
	}

	@Override
	public ASN1Encodable readObject() throws IOException {
		return _parser.readObject();
	}

	@Override
	public ASN1Primitive getLoadedObject() throws IOException {
		return new DERSet(_parser.readVector(), false);
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		try {
			return getLoadedObject();
		} catch (IOException e) {
			throw new ASN1ParsingException(e.getMessage(), e);
		}
	}

}
