package eu.europa.esig.dss.cookbook.example.snippets.ws.rest;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO;
import eu.europa.esig.dss.ws.cert.validation.rest.RestCertificateValidationServiceImpl;
import eu.europa.esig.dss.ws.cert.validation.rest.client.RestCertificateValidationService;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;

import java.io.File;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

public class RestCertificateValidationServiceSnippet {

    @SuppressWarnings("unused")
    public void demo() throws Exception {
        // tag::demo[]

        // Instantiate a rest certificate validation service
        RestCertificateValidationService validationService = new RestCertificateValidationServiceImpl();

        // Instantiate the certificate to be validated
        CertificateToken certificateToken = DSSUtils.loadCertificate(new File("src/test/resources/CZ.cer"));
        RemoteCertificate remoteCertificate = RemoteCertificateConverter.toRemoteCertificate(certificateToken);

        // Instantiate certificate chain (optional, to be used when certificate chain cannot be obtained by AIA)
        CertificateToken caCertificate = DSSUtils.loadCertificate(new File("src/test/resources/CA_CZ.cer"));
        RemoteCertificate issuerRemoteCertificate = RemoteCertificateConverter.toRemoteCertificate(caCertificate);

        CertificateToken rootCertificate = DSSUtils.loadCertificate(new File("src/test/resources/ROOT_CZ.cer"));
        RemoteCertificate rootRemoteCertificate = RemoteCertificateConverter.toRemoteCertificate(rootCertificate);

        // Define validation time (optional, if not defined the current time will be used)
        Calendar calendar = Calendar.getInstance();
        calendar.set(2018, 12, 31);
        Date validationDate = calendar.getTime();

        // Create objects containing parameters to be provided to the validation process
        CertificateToValidateDTO certificateToValidateDTO = new CertificateToValidateDTO(
                remoteCertificate, Arrays.asList(issuerRemoteCertificate, rootRemoteCertificate), validationDate);

        // Validate the certificate
        CertificateReportsDTO reportsDTO = validationService.validateCertificate(certificateToValidateDTO);

        // end::demo[]
    }

}
