package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.ArchiveTimestampType;

public class ArchiveTimestampTypeParser {

	private ArchiveTimestampTypeParser() {
	}

	public static ArchiveTimestampType parse(String v) {
		return ArchiveTimestampType.valueOf(v);
	}

	public static String print(ArchiveTimestampType v) {
		return v.name();
	}

}
