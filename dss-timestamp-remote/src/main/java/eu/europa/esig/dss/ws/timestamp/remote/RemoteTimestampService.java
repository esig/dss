package eu.europa.esig.dss.ws.timestamp.remote;

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.timestamp.dto.TimestampResponseDTO;

public class RemoteTimestampService {

	private static final Logger LOG = LoggerFactory.getLogger(RemoteTimestampService.class);
	
	private TSPSource tspSource;
	
	public void setTSPSource(TSPSource tspSource) {
		this.tspSource = tspSource;
	}
	
	public TimestampResponseDTO getTimestampResponse(final DigestAlgorithm digestAlgorithm, final byte[] value) throws DSSException {
		Objects.requireNonNull(tspSource, "TSPSource must be not null!");
		LOG.info("Timestamp request in process...");
		Objects.requireNonNull(digestAlgorithm, "digestAlgorithm must be not null!");
		Objects.requireNonNull(value, "value must be not null!");
		TimestampBinary timestampBinary = tspSource.getTimeStampResponse(digestAlgorithm, value);
		if (timestampBinary != null && Utils.isArrayNotEmpty(timestampBinary.getBytes())) {
			LOG.info("Timestamp is obtained.");
			return toTimestampResponseDTO(timestampBinary);
		}
		throw new DSSException("The obtained TimestampToken response is null or empty!");
	}
	
	private TimestampResponseDTO toTimestampResponseDTO(TimestampBinary timestampBinary) {
		TimestampResponseDTO timestampDTO = new TimestampResponseDTO();
		timestampDTO.setBinaries(timestampBinary.getBytes());
		return timestampDTO;
	}

}
