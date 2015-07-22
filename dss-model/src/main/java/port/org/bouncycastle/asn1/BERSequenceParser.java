package port.org.bouncycastle.asn1;

import java.io.IOException;

public class BERSequenceParser implements ASN1SequenceParser {

	private ASN1StreamParser _parser;

	BERSequenceParser(ASN1StreamParser parser) {
		this._parser = parser;
	}

	@Override
	public ASN1Encodable readObject() throws IOException {
		return _parser.readObject();
	}

	@Override
	public ASN1Primitive getLoadedObject() throws IOException {
		return new BERSequence(_parser.readVector());
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		try {
			return getLoadedObject();
		} catch (IOException e) {
			throw new IllegalStateException(e.getMessage());
		}
	}

}
