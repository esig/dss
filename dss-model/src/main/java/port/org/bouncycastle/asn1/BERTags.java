package port.org.bouncycastle.asn1;

public interface BERTags {

	int BOOLEAN = 0x01;
	int INTEGER = 0x02;
	int BIT_STRING = 0x03;
	int OCTET_STRING = 0x04;
	int NULL = 0x05;
	int OBJECT_IDENTIFIER = 0x06;
	int EXTERNAL = 0x08;
	int ENUMERATED = 0x0a;
	int SEQUENCE = 0x10;
	int SEQUENCE_OF = 0x10; // for completeness - used to model a SEQUENCE of the same type.
	int SET = 0x11;
	int SET_OF = 0x11; // for completeness - used to model a SET of the same type.

	int NUMERIC_STRING = 0x12;
	int PRINTABLE_STRING = 0x13;
	int T61_STRING = 0x14;
	int VIDEOTEX_STRING = 0x15;
	int IA5_STRING = 0x16;
	int UTC_TIME = 0x17;
	int GENERALIZED_TIME = 0x18;
	int GRAPHIC_STRING = 0x19;
	int VISIBLE_STRING = 0x1a;
	int GENERAL_STRING = 0x1b;
	int UNIVERSAL_STRING = 0x1c;
	int BMP_STRING = 0x1e;
	int UTF8_STRING = 0x0c;

	int CONSTRUCTED = 0x20;
	int APPLICATION = 0x40;
	int TAGGED = 0x80;

}
