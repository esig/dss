package port.org.bouncycastle.asn1;

import java.io.IOException;

public interface ASN1TaggedObjectParser extends ASN1Encodable, InMemoryRepresentable {

	int getTagNo();

	ASN1Encodable getObjectParser(int tag, boolean isExplicit) throws IOException;

}
