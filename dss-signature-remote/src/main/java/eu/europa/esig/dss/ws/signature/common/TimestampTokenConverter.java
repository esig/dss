package eu.europa.esig.dss.ws.signature.common;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TSPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampInclude;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.ws.dto.TimestampDTO;
import eu.europa.esig.dss.ws.dto.TimestampIncludeDTO;

public class TimestampTokenConverter {

	private static final Logger LOG = LoggerFactory.getLogger(TimestampTokenConverter.class);
	
	public static List<TimestampToken> toTimestampTokens(List<TimestampDTO> timestampDTOs) {
		List<TimestampToken> timestampTokens = new ArrayList<TimestampToken>();
		if (Utils.isCollectionNotEmpty(timestampDTOs)) {
			for (TimestampDTO timestampDTO : timestampDTOs) {
				if (timestampDTO != null && Utils.isArrayNotEmpty(timestampDTO.getBinaries())) {
					try {
						timestampTokens.add(toTimestampToken(timestampDTO));
					} catch (DSSException e) {
						LOG.warn(e.getMessage());
					}
				}
			}
		}
		return timestampTokens;
	}
	
	public static TimestampToken toTimestampToken(TimestampDTO timestampDTO) throws DSSException {
		Objects.requireNonNull(timestampDTO, "TimestampDTO cannot be null!");
		Objects.requireNonNull(timestampDTO.getBinaries(), "TimestampDTO binaries cannot be null!");
		Objects.requireNonNull(timestampDTO.getType(), "TimestampDTO type cannot be null!");
		try {
			TimestampToken timestampToken = new TimestampToken(timestampDTO.getBinaries(), timestampDTO.getType());
			timestampToken.setCanonicalizationMethod(timestampDTO.getCanonicalizationMethod());
			if (timestampDTO.getIncludes() != null) {
				timestampToken.setTimestampIncludes(toTimestampIncludes(timestampDTO.getIncludes()));
			}
			return timestampToken;
		} catch (TSPException | IOException | CMSException e) {
			throw new DSSException(String.format("Cannot convert a TimestampDTO to TimestampToken class, reason : {}", e.getMessage()));
		}
	}
	
	public static TimestampDTO toTimestampDTO(TimestampToken timestampToken) {
		Objects.requireNonNull(timestampToken, "TimestampToken cannot be null!");
		TimestampDTO timestampDTO = new TimestampDTO(timestampToken.getEncoded(), timestampToken.getTimeStampType());
		timestampDTO.setCanonicalizationMethod(timestampToken.getCanonicalizationMethod());
		timestampDTO.setIncludes(toTimestampIncludeDTOs(timestampToken.getTimestampIncludes()));
		return timestampDTO;
	}
	
	private static List<TimestampInclude> toTimestampIncludes(List<TimestampIncludeDTO> timestampIncludeDTOs) {
		List<TimestampInclude> timestampIncludes = new ArrayList<TimestampInclude>();
		if (Utils.isCollectionNotEmpty(timestampIncludeDTOs)) {
			for (TimestampIncludeDTO timestampIncludeDTO : timestampIncludeDTOs) {
				if (timestampIncludeDTO != null) {
					timestampIncludes.add(new TimestampInclude(timestampIncludeDTO.getURI(), timestampIncludeDTO.isReferencedData()));
				}
			}
		}
		return timestampIncludes;
	}
	
	private static List<TimestampIncludeDTO> toTimestampIncludeDTOs(List<TimestampInclude> timestampIncludes) {
		List<TimestampIncludeDTO> timestampIncludeDTOs = new ArrayList<TimestampIncludeDTO>();
		if (Utils.isCollectionNotEmpty(timestampIncludes)) {
			for (TimestampInclude timestampInclude : timestampIncludes) {
				if (timestampInclude != null) {
					timestampIncludeDTOs.add(new TimestampIncludeDTO(timestampInclude.getURI(), timestampInclude.isReferencedData()));
				}
			}
		}
		return timestampIncludeDTOs;
	}

}
