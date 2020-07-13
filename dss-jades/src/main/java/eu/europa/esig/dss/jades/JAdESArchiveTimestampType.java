package eu.europa.esig.dss.jades;

import java.util.HashMap;
import java.util.Map;

import eu.europa.esig.dss.enumerations.ArchiveTimestampType;

/**
 * Contains a list of enumerations for JAdES 'timestamped' parameter of 'arcTst' object
 *
 */
public enum JAdESArchiveTimestampType {
	
	TIMESTAMPED_ALL("all", ArchiveTimestampType.JAdES_ALL),
	
	TIMESTAMPED_PREVIOUS_ARC_TST("previousArcTst", ArchiveTimestampType.JAdES_PREVIOUS_ARC_TST);
	
	/**
	 * Represents the enum value used in JAdES
	 */
	private final String value;
	
	private final ArchiveTimestampType archiveTimestampType;
	
	private static Map<String, JAdESArchiveTimestampType> valueMap = registerValues();
	
	private static Map<String, JAdESArchiveTimestampType> registerValues() {
		Map<String, JAdESArchiveTimestampType> valueMap = new HashMap<>();
		for (JAdESArchiveTimestampType jadesHeaderEnum : values()) {
			valueMap.put(jadesHeaderEnum.getValue(), jadesHeaderEnum);
		}
		return valueMap;
	}
	
	private JAdESArchiveTimestampType(String value, ArchiveTimestampType archiveTimestampType) {
		this.value = value;
		this.archiveTimestampType = archiveTimestampType;
	}
	
	/**
	 * Returns JAdES value associated with the enum
	 * 
	 * @return {@link String} value
	 */
	public String getValue() {
		return value;
	}
	
	/**
	 * Returns the related {@code ArchiveTimestampType}
	 * 
	 * @return {@link ArchiveTimestampType}
	 */
	public ArchiveTimestampType getAssociatedArchiveTimestampType() {
		return archiveTimestampType;
	}
	
	/**
	 * Returns {@code JAdESArchiveTimestampType} based on the given JAdES value
	 * 
	 * @param value {@link String} JAdES value to get {@link JAdESArchiveTimestampType} for
	 * @return {@link JAdESArchiveTimestampType}
	 */
	public static JAdESArchiveTimestampType forJsonValue(String value) {
		return valueMap.get(value);
	}

}
