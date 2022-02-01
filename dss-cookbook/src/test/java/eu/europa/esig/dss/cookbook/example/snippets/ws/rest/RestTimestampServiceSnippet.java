package eu.europa.esig.dss.cookbook.example.snippets.ws.rest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.timestamp.dto.TimestampResponseDTO;
import eu.europa.esig.dss.ws.timestamp.remote.rest.RestTimestampServiceImpl;
import eu.europa.esig.dss.ws.timestamp.remote.rest.client.RestTimestampService;

public class RestTimestampServiceSnippet {

    @SuppressWarnings("unused")
    public void demo() throws Exception {
        // tag::demo[]

        // Initialize the rest client
        RestTimestampService timestampService = new RestTimestampServiceImpl();

        // Initialize data to be timestamped (e.g. a document)
        byte[] contentToBeTimestamped = "Hello World!".getBytes();

        // Apply hash-function on the data
        byte[] digestValue = DSSUtils.digest(DigestAlgorithm.SHA256, contentToBeTimestamped);

        // Create an object to be provided to the timestamping service
        // NOTE: ensure that the same DigestAlgorithm is used in both method calls
        DigestDTO digest = new DigestDTO(DigestAlgorithm.SHA256, digestValue);

        // Timestamp the digest
        TimestampResponseDTO timestampResponse = timestampService.getTimestampResponse(digest);

        // end::demo[]
    }

}
