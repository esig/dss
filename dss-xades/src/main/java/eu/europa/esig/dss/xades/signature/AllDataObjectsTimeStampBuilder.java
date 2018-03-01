package eu.europa.esig.dss.xades.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.x509.tsp.TSPSource;
import eu.europa.esig.dss.xades.DSSXMLUtils;

public class AllDataObjectsTimeStampBuilder {

	private final TSPSource tspSource;
	private final DigestAlgorithm digestAlgorithm;
	private final String canonicalizationAlgorithm;

	public AllDataObjectsTimeStampBuilder(TSPSource tspSource, DigestAlgorithm digestAlgorithm) {
		this(tspSource, digestAlgorithm, null);
	}

	public AllDataObjectsTimeStampBuilder(TSPSource tspSource, DigestAlgorithm digestAlgorithm, String canonicalizationAlgorithm) {
		this.tspSource = tspSource;
		this.digestAlgorithm = digestAlgorithm;
		this.canonicalizationAlgorithm = canonicalizationAlgorithm;
	}

	public TimestampToken build(DSSDocument document) {
		return build(Arrays.asList(document));
	}

	public TimestampToken build(List<DSSDocument> documents) {
		byte[] digestToTimestamp = DSSUtils.digest(digestAlgorithm, getToBeDigested(documents));
		return build(digestToTimestamp);
	}

	private TimestampToken build(byte[] digestToTimestamp) {
		TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, digestToTimestamp);
		TimestampToken token = new TimestampToken(timeStampResponse, TimestampType.ALL_DATA_OBJECTS_TIMESTAMP, new CertificatePool());
		token.setCanonicalizationMethod(canonicalizationAlgorithm);
		return token;
	}

	private byte[] getToBeDigested(List<DSSDocument> documents) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			for (DSSDocument document : documents) {
				byte[] binaries = DSSUtils.toByteArray(document);
				if (Utils.isStringNotEmpty(canonicalizationAlgorithm)) {
					binaries = DSSXMLUtils.canonicalize(canonicalizationAlgorithm, binaries);
				}
				baos.write(binaries);
			}
			return baos.toByteArray();
		} catch (IOException e) {
			throw new DSSException("Unable to compute the data to be digested", e);
		}
	}

}
