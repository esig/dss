package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicValidation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureDigestReference;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.enums.TypeOfProof;
import eu.europa.esig.validationreport.jaxb.POEProvisioningType;
import eu.europa.esig.validationreport.jaxb.POEType;
import eu.europa.esig.validationreport.jaxb.SignatureReferenceType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.VOReferenceType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationTimeInfoType;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS1988ExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void dss1988Test() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/dss-1988.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
        assertNotNull(etsiValidationReport);
        List<SignatureValidationReportType> signatureValidationReports = etsiValidationReport.getSignatureValidationReport();
        assertEquals(1, signatureValidationReports.size());

        SignatureValidationReportType signatureValidationReport = signatureValidationReports.get(0);
        ValidationTimeInfoType validationTimeInfo = signatureValidationReport.getValidationTimeInfo();
        assertNotNull(validationTimeInfo);
        assertEquals(diagnosticData.getValidationDate(), validationTimeInfo.getValidationTime());

        POEType bestSignatureTime = validationTimeInfo.getBestSignatureTime();
        assertNotNull(bestSignatureTime);

        assertEquals(TypeOfProof.VALIDATION, bestSignatureTime.getTypeOfProof());
        VOReferenceType poeObject = bestSignatureTime.getPOEObject();
        assertNotNull(poeObject);

        List<Object> voReference = poeObject.getVOReference();
        assertNotNull(voReference);
        assertEquals(1, voReference.size());

        Object timestampObject = voReference.get(0);
        assertInstanceOf(ValidationObjectType.class, timestampObject);
        ValidationObjectType timestampValidationObject = (ValidationObjectType) timestampObject;
        String timestampId = timestampValidationObject.getId();
        assertNotNull(timestampId);

        ValidationObjectListType signatureValidationObjects = etsiValidationReport.getSignatureValidationObjects();
        assertNotNull(signatureValidationObjects);
        assertTrue(Utils.isCollectionNotEmpty(signatureValidationObjects.getValidationObject()));
        for (ValidationObjectType validationObject : signatureValidationObjects.getValidationObject()) {
            if (timestampId.equals(validationObject.getId())) {
                timestampValidationObject = validationObject;
                break;
            }
        }

        assertEquals(ObjectType.TIMESTAMP, timestampValidationObject.getObjectType());
        POEProvisioningType poeProvisioning = timestampValidationObject.getPOEProvisioning();
        assertNotNull(poeProvisioning);

        List<VOReferenceType> timestampedObjects = poeProvisioning.getValidationObject();
        assertTrue(Utils.isCollectionNotEmpty(timestampedObjects));

        List<SignatureReferenceType> signatureReferences = poeProvisioning.getSignatureReference();
        assertEquals(1, signatureReferences.size());

        XmlSignatureDigestReference signatureDigestReference = diagnosticData.getSignatures().get(0).getSignatureDigestReference();

        SignatureReferenceType signatureReferenceType = signatureReferences.get(0);
        assertEquals(signatureDigestReference.getCanonicalizationMethod(), signatureReferenceType.getCanonicalizationMethod());
        assertEquals(signatureDigestReference.getDigestMethod(), DigestAlgorithm.forXML(signatureReferenceType.getDigestMethod()));
        assertArrayEquals(signatureDigestReference.getDigestValue(), signatureReferenceType.getDigestValue());

        DetailedReport detailedReport = reports.getDetailedReport();

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlSAV sav = signatureBBB.getSAV();
        assertEquals(1, sav.getConclusion().getErrors().size());

        XmlCryptographicValidation cryptographicValidation = sav.getCryptographicValidation();
        assertEquals(SignatureAlgorithm.RSA_SHA1, SignatureAlgorithm.forXML(cryptographicValidation.getAlgorithm().getUri()));
        assertEquals("2048", cryptographicValidation.getAlgorithm().getKeyLength());

        checkReports(reports);
    }

}
